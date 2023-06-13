#![allow(clippy::missing_safety_doc)]
#![feature(core_intrinsics)]
#![feature(start)]
#![feature(const_btree_new)]
#![feature(unchecked_math)]
#![feature(naked_functions)]
#![feature(map_first_last)]
#![feature(asm_sym)]
#![feature(asm_const)]
#![feature(slice_internals)]

pub mod engine;
pub mod handlers;
pub mod harness;
pub mod signals;
#[macro_use]
pub mod utils;

use clap::{App, Arg};
use core::time::Duration;
use std::fs::metadata;
use std::fs::File;
use std::io::Read;
#[cfg(feature = "full_trace")]
use std::io::Write;
use std::time::SystemTime;
use std::{env, fs, path::PathBuf};
use svd_parser as svd;

use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        os::Cores,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
        AsSlice,
    },
    corpus::{Corpus, OnDiskCorpus},
    events::EventConfig,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        Tokens,
    },
    observers::{StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};

#[start]
pub fn main(_: isize, _: *const *const u8) -> isize {
    let options = App::new("SAFIREFUZZ")
        .version("1.0.0")
        .author("Lukas S. <@pr0me>")
        .about("efficient ARM firmware rehosting and fuzzing.")
        .arg(
            Arg::with_name("binary")
                .short("b")
                .long("binary")
                .value_name("BIN")
                .help("Sets path firmware binary to be loaded")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input_file")
                .value_name("INPUT")
                .help("Specifies path to input file/directory")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("svd-file")
                .short("svd")
                .long("svd-file")
                .value_name("SVD")
                .help("Specifies path to svd profile")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("token-file")
                .short("t")
                .long("token-file")
                .value_name("TOKENS")
                .help("Specifies path to file with token dictionary")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("broker-port")
                .short("p")
                .long("broker-port")
                .value_name("PORT")
                .help("Specifies the port the LibAFL broker is running on (default: 1337)")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cores")
                .short("c")
                .long("cores")
                .value_name("CORES")
                .help("Specifies the CPU IDs used for fuzzing, e.g., '1,2-4,6' or 'all'")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("executions")
                .short("n")
                .long("num_executions")
                .value_name("N")
                .help("Number of Executions in File mode")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("fuzz")
                .short("f")
                .long("fuzz")
                .help("Starts as fuzzer")
                .required(false),
        )
        .get_matches();

    let bin_path = options.value_of("binary").unwrap();
    let mut f_bin = File::open(bin_path).expect("Failed to open input file");

    let svd_opt = options.value_of("svd-file");
    if let Some(svd_val) = svd_opt {
        let svd_path = svd_val;
        let xml = &mut String::new();
        File::open(svd_path)
            .expect("Failed to open svd file")
            .read_to_string(xml)
            .expect("Failed to read svd file.");
        println!("{:#x?}", svd::parse(xml));
    }

    unsafe {
        f_bin
            .read_to_end(&mut engine::BINARY)
            .expect("Failed to read input file");

        // executes single runs on specified input
        if !options.is_present("fuzz") {
            let input_opt = options.value_of("input");
            let num_execs =
                // usize::from_str_radix(options.value_of("executions").unwrap_or("1"), 10).unwrap();
                options.value_of("executions").unwrap_or("1").parse::<usize>().unwrap();

            if let Some(input_val) = input_opt {
                engine::init(&engine::BINARY).unwrap();

                let input_path = input_val;
                let md = metadata(input_path).unwrap();

                if md.is_file() {
                    engine::FUZZ_INPUT.clear();
                    let mut f_in = File::open(input_path).expect("Failed to open input file");
                    f_in.read_to_end(&mut engine::FUZZ_INPUT)
                        .expect("Failed to read corpus file");
                    engine::FUZZ_LEN = engine::FUZZ_INPUT.len() as _;

                    println!(
                        "[*] Accepted fuzz input from file (len: {})",
                        engine::FUZZ_LEN
                    );

                    #[cfg(feature = "full_trace")]
                    let mut cov = engine::COV_AREA_PTR[0..512].to_owned();

                    engine::START_TIME = SystemTime::now();
                    for n in 0..num_execs {
                        if n % 8192 == 0 {
                            println!(
                                "exec/s: {}",
                                engine::NUM_EXECS as f32
                                    / engine::START_TIME.elapsed().unwrap().as_secs_f32()
                            );
                            engine::START_TIME = SystemTime::now();
                            engine::NUM_EXECS = 0;
                        }

                        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                        let ret = engine::start_execution(engine::ENTRY, &engine::FUZZ_INPUT[..]);
                        if ret == 3 {
                            println!("[!] Timeout reported");
                        }
                        engine::NUM_EXECS += 1;

                        #[cfg(feature = "full_trace")]
                        if n > 0 {
                            if &engine::COV_AREA_PTR[0..512] != cov {
                                println!("MISMATCH");
                                // panic!();
                            }
                            if engine::TRACE != engine::LAST_TRACE {
                                let mut f = File::create("mismatch_trace.dump")
                                    .expect("Unable to create file");
                                for i in &engine::TRACE {
                                    writeln!(f, "{:#x}", i).unwrap();
                                }
                                let mut f =
                                    File::create("last_trace.dump").expect("Unable to create file");
                                for i in &engine::LAST_TRACE {
                                    writeln!(f, "{:#x}", i).unwrap();
                                }
                                std::process::abort();
                            }
                        } else {
                            // save coverage data from first execution
                            cov = engine::COV_AREA_PTR[0..512].to_vec();
                        }
                    }
                    println!(
                        "exec/s: {}",
                        engine::NUM_EXECS as f32
                            / engine::START_TIME.elapsed().unwrap().as_secs_f32()
                    );
                    println!(
                        "[i] COV HASH: {:#x}",
                        utils::calculate_hash(&engine::COV_AREA_PTR)
                    );
                } else {
                    let paths = fs::read_dir(input_path).unwrap();
                    println!("[+] Executing Inputs from Directory {}", input_path);
                    let mut curr_path: PathBuf;
                    for p in paths {
                        curr_path = p.unwrap().path();
                        let md = metadata(&curr_path).unwrap();
                        if md.is_dir() {
                            println!(
                                "[!] Skipping directory {}: This function does not recurse.",
                                curr_path.display()
                            );
                            continue;
                        }

                        engine::FUZZ_INPUT.clear();
                        let mut f_in = File::open(&curr_path).expect("Failed to open input file");
                        f_in.read_to_end(&mut engine::FUZZ_INPUT)
                            .expect("Failed to read corpus file");
                        engine::FUZZ_LEN = engine::FUZZ_INPUT.len() as _;
                        println!(
                            "[+] Accepted fuzz input from file {:?} (len: {})",
                            curr_path,
                            engine::FUZZ_LEN
                        );
                        engine::START_TIME = SystemTime::now();
                        for _ in 0..num_execs {
                            if engine::NUM_EXECS % 8192 == 0 {
                                println!(
                                    "exec/s: {}",
                                    engine::NUM_EXECS as f32
                                        / engine::START_TIME.elapsed().unwrap().as_secs_f32()
                                );
                                engine::START_TIME = SystemTime::now();
                                engine::NUM_EXECS = 0;
                            }
                            let ret =
                                engine::start_execution(engine::ENTRY, &engine::FUZZ_INPUT[..]);
                            if ret == 3 {
                                println!("[!] Timeout reported");
                            }
                            engine::NUM_EXECS += 1;
                        }
                        println!(
                            "exec/s: {}",
                            engine::NUM_EXECS as f32
                                / engine::START_TIME.elapsed().unwrap().as_secs_f32()
                        );
                        println!(
                            "[i] COV HASH: {:#x}",
                            utils::calculate_hash(&engine::COV_AREA_PTR)
                        );
                    }
                }
            }

            return 0;
        }
    }

    let broker_port: u16 = if options.is_present("broker-port") {
        options
            .value_of("broker-port")
            .unwrap()
            .parse::<u16>()
            .unwrap()
    } else {
        1337
    };

    let cores: Cores = if options.is_present("cores") {
        println!("{:?}", options.value_of("cores"));
        Cores::from_cmdline(options.value_of("cores").unwrap()).unwrap()
    } else {
        Cores::from(vec![2_usize, 3_usize])
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let monitor = MultiMonitor::new(|s| println!("{}", s));

    let input_opt = options.value_of("input");
    let input_dir: &str;
    if let Some(input_val) = input_opt {
        input_dir = input_val;
        let md = metadata(input_dir).expect("Failed to read specified Input directory");
        if !md.is_dir() {
            panic!("Specified Input Option does not seem to be a directory")
        }
        println!("[!] {}", input_dir);
    } else {
        input_dir = "./corpus";
    }

    let mut run_client = |state: Option<StdState<_, _, _, _, _>>,
                          mut restarting_mgr,
                          _size: usize| {
        let corpus_dirs = &[PathBuf::from(input_dir)];
        let objective_dir = PathBuf::from("./crashes");
        let queue_dir = PathBuf::from("./queue");

        // Create an observation channel using the coverage map
        let edges = unsafe { &mut engine::COV_AREA_PTR };
        let edges_observer = StdMapObserver::new("edges", edges);

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // The state of the edges feedback.
        let feedback_state = MapFeedbackState::with_observer(&edges_observer);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new_with_observer(&time_observer)
        );

        let objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos()),
                // InMemoryCorpus::new(),
                OnDiskCorpus::new(queue_dir).unwrap(),
                OnDiskCorpus::new(objective_dir).unwrap(),
                tuple_list!(feedback_state),
            )
        });

        if options.is_present("token-file") && state.metadata().get::<Tokens>().is_none() {
            println!("[+] Adding tokens to mutator dictionary");
            state.add_metadata(Tokens::from_file(std::path::Path::new(
                options.value_of("token-file").unwrap(),
            ))?);
        }

        // Setup a basic mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            unsafe {
                let ret = engine::start_execution(engine::ENTRY, buf);
                match ret {
                    0 => ExitKind::Ok,
                    3 => ExitKind::Timeout,
                    _ => ExitKind::Crash,
                }
            }
            // ExitKind::Ok
        };

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = TimeoutExecutor::new(
            InProcessExecutor::new(
                &mut harness,
                tuple_list!(edges_observer, time_observer),
                &mut fuzzer,
                &mut state,
                &mut restarting_mgr,
            )?,
            Duration::new(5, 0),
        );

        println!("[*] STARTING FUZZER");

        // The actual target run starts here.
        unsafe {
            engine::init(&engine::BINARY).unwrap();
        }

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            state
                .load_initial_inputs_forced(
                    &mut fuzzer,
                    &mut executor,
                    &mut restarting_mgr,
                    corpus_dirs,
                )
                .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", corpus_dirs));
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        // executor.set_timeout(Duration::from_millis(800));
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        Ok(())
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }

    0
}
