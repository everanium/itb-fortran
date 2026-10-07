! Long-run stress harness. The loop utility holds one Pipeline handle
! per exercised cipher surface for minutes, hammers it with
! concurrent encrypt -> decrypt -> compare round-trips from N worker
! threads, rotates the outer masters and reopens the handle from its
! session blob on a schedule, and reports whether the process
! survived with every byte intact. It is the Fortran binding's
! counterpart of the Go harness under tools/loop: the same flags, the
! same round structure, the same summary in both renderings.
!
! The default shape is full production: the Streaming AEAD profile
! with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
! inner hash, 1024-bit keys, and the compile-in 512-bit nonce width,
! driven through a stream session by three workers for five minutes
! on 16 MiB plaintexts. Every worker owns a distinct CSPRNG-generated
! plaintext held for the whole run, so any cross-call state leakage
! inside the Pipeline surfaces as a data mismatch between workers
! rather than cancelling out.
!
! A failure is one of two things. A cipher, rekey or load call that
! returns a non-OK status is a worker error: the run stops, the
! summary lists it, the verdict is FAIL and the exit code 1. A
! round-trip that returns without error but with different bytes is a
! data mismatch: the process terminates on the spot with exit code 3,
! printing the worker, the iteration and the first differing offset,
! and no summary -- the state that produced the wrong bytes is the
! evidence. A crash inside the shared library or the host runtime has
! no exit code of its own here; surfacing it is what the utility is
! for.
!
! Usage:
!
!   ./loop --duration 5m --goroutines 3 --shape stream --hash areion512 \
!          --mac hmac-blake3 --payload-size 16MB --memlimit auto \
!          --parallax on --wrapper on
!
! Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
! then the partial summary prints.

module loop_flags
  use, intrinsic :: iso_c_binding
  use itb3
  use loop_size
  use loop_state
  use loop_worker, only: parse_shape, shape_name
  use loop_payload, only: parse_payload_mode, payload_mode_name
  implicit none
  private

  public :: parse_flags, PARSE_OK, PARSE_HELP, PARSE_ERROR

  integer, parameter :: PARSE_OK = 0
  integer, parameter :: PARSE_HELP = 1
  integer, parameter :: PARSE_ERROR = 2

  integer, parameter :: N_FLAGS = 25

  ! One raw flag value. A deferred-length component rather than a
  ! fixed-width one so no ceiling of the utility's own can reject a
  ! value the library would have had something to say about.
  type :: slot_t
    character(:), allocatable :: text
  end type

  integer, parameter :: K_INT = 1
  integer, parameter :: K_INT64 = 2
  integer, parameter :: K_UINT64 = 3
  integer, parameter :: K_STRING = 4
  integer, parameter :: K_BOOL = 5

  ! The flag table, in alphabetical order (the order the usage
  ! prints). Names, type labels, help strings and defaults are the
  ! output contract; the default suffix is rendered for the integer
  ! and string kinds only, exactly as the reference composes it.
  character(len=17), parameter :: FLAG_NAME(N_FLAGS) = [ &
      "barrier-fill     ", "blob-cycle-every ", "blob-mode        ", &
      "chunk-size       ", "drbg             ", "duration         ", &
      "gogc             ", "gomaxprocs       ", &
      "goroutines       ", "hash             ", "iterations       ", &
      "json-output      ", "key-bits         ", "mac              ", &
      "memlimit         ", "memprofile       ", "nonce-bits       ", &
      "parallax         ", "payload-mode     ", "payload-size     ", &
      "profile          ", "rekey-every      ", "seed             ", &
      "shape            ", "wrapper          "]

  character(len=8), parameter :: FLAG_TYPE(N_FLAGS) = [ &
      "int     ", "int     ", "int     ", "string  ", "string  ", &
      "duration", "int     ", &
      "int     ", "int     ", "string  ", "int     ", "        ", &
      "int     ", "string  ", "string  ", "string  ", "int     ", &
      "string  ", "string  ", "string  ", "string  ", "int     ", &
      "uint    ", "string  ", "string  "]

  integer, parameter :: FLAG_KIND(N_FLAGS) = [ &
      K_INT, K_INT64, K_INT, K_STRING, K_STRING, K_STRING, K_INT, &
      K_INT, K_INT, K_STRING, K_INT64, K_BOOL, &
      K_INT, K_STRING, K_STRING, K_STRING, K_INT, &
      K_STRING, K_STRING, K_STRING, K_STRING, K_INT64, &
      K_UINT64, K_STRING, K_STRING]

  character(len=16), parameter :: FLAG_DEFAULT(N_FLAGS) = [ &
      "0               ", "0               ", "1               ", &
      "0               ", "                ", "5m              ", &
      "0               ", "0               ", &
      "3               ", "areion512       ", "0               ", &
      "false           ", "0               ", "hmac-blake3     ", &
      "auto            ", "                ", "0               ", &
      "on              ", "fixed           ", "16MB            ", &
      "                ", "0               ", "0               ", &
      "stream          ", "on              "]

contains

  ! The help text of one flag, in table order. A select case rather
  ! than an array because several of these run past the 132-column
  ! line limit of free-form Fortran and would have to be broken
  ! inside an array constructor.
  function flag_help(i) result(s)
    integer, intent(in)       :: i
    character(:), allocatable :: s

    select case (i)
    case (1)
      s = "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32;"// &
          " 0 = profile default (1)"
    case (2)
      s = "reopen each pipeline from its session blob every N"// &
          " iterations per worker; 0 = never"
    case (3)
      s = "container floor sizing mode: 1 (per-region, default)"// &
          " | 2 (per-container)"
    case (4)
      s = "streaming chunk-size budget (e.g. 4MB); 0 = profile"// &
          " default; inert for pure message shape"
    case (5)
      s = "DRBG fill primitive name (see itb3 drbgs); empty ="// &
          " profile default (auto tier)"
    case (6)
      s = "run duration (Go format: 30s / 5m / 1h); ignored when"// &
          " --iterations > 0"
    case (7)
      s = "GC trigger percentage; 0 = leave the runtime default"
    case (8)
      s = "Go runtime GOMAXPROCS override; 0 = inherit from the"// &
          " environment"
    case (9)
      s = "concurrent workers (1..10); on runtimes without"// &
          " parallelism values above 1 are clamped to 1"
    case (10)
      s = "inner ITB hash primitive name"
    case (11)
      s = "fixed per-worker iteration count; 0 = duration-based"
    case (12)
      s = "print the final summary as one compact JSON object"// &
          " instead of log lines"
    case (13)
      s = "per-seed key width in bits: 512 | 1024 | 2048;"// &
          " 0 = profile default (1024)"
    case (14)
      s = "MAC primitive name"
    case (15)
      s = "Go heap soft limit: auto (1GiB when goroutines <= 3,"// &
          " else 256MiB, applied only when the runtime has no"// &
          " limit) or a size (e.g. 512MB)"
    case (16)
      s = "write a Go runtime heap profile (pprof) to this path at"// &
          " the end of the run; empty = none"
    case (17)
      s = "on-wire nonce width in bits: 128 | 256 | 512;"// &
          " 0 = profile default (512)"
    case (18)
      s = "parallax layer: on | off"
    case (19)
      s = "plaintext content: fixed | rotating | pattern-zero |"// &
          " pattern-ff | pattern-ascii"
    case (20)
      s = "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"
    case (21)
      s = "exercise this single registered triple profile"// &
          " (overrides --shape with the profile's surface);"// &
          " empty = shape-based profile pair"
    case (22)
      s = "rotate the parallax + wrapper masters via Rekey every N"// &
          " iterations per worker; 0 = never"
    case (23)
      s = "deterministic plaintext RNG seed for bug reproduction,"// &
          " NOT for security testing (pipeline keys stay"// &
          " CSPRNG-drawn); 0 = crypto/rand plaintexts"
    case (24)
      s = "cipher surface to exercise: stream | message |"// &
          " stream_one_shot | both"
    case default
      s = "wrapper layer: on | off"
    end select
  end function

  ! Prints the usage to stderr, one block per flag in table order.
  subroutine usage()
    integer :: i
    character(:), allocatable :: head, body

    call emit(2_c_int, "Usage of loop:")
    do i = 1, N_FLAGS
      head = "  -"//trim(FLAG_NAME(i))
      if (len_trim(FLAG_TYPE(i)) > 0) head = head//" "//trim(FLAG_TYPE(i))
      call emit(2_c_int, head)
      body = "    "//achar(9)//flag_help(i)
      ! Fortran-specific. The default-value suffix is composed by
      ! hand; a flag library that appends its own renders it itself.
      if (FLAG_KIND(i) == K_INT) then
        if (trim(FLAG_DEFAULT(i)) /= "0") then
          body = body//" (default "//trim(FLAG_DEFAULT(i))//")"
        end if
      else if (FLAG_KIND(i) == K_STRING) then
        if (len_trim(FLAG_DEFAULT(i)) > 0) then
          body = body//' (default "'//trim(FLAG_DEFAULT(i))//'")'
        end if
      end if
      call emit(2_c_int, body)
    end do
  end subroutine

  ! Whether text is a well-formed value for the flag's kind. The
  ! lexical check happens as the value is assigned, so a malformed
  ! value is reported against the flag that carried it.
  function value_ok(kind, text) result(ok)
    integer, intent(in)      :: kind
    character(*), intent(in) :: text
    logical                  :: ok
    integer(c_int64_t) :: v
    integer            :: first

    ok = .false.
    select case (kind)
    case (K_STRING)
      ok = .true.
    case (K_BOOL)
      ok = (text == "true" .or. text == "false")
    case (K_UINT64)
      ok = parse_u64(text, v)
    case (K_INT, K_INT64)
      if (len(text) == 0) return
      first = 1
      if (text(1:1) == '-' .or. text(1:1) == '+') first = 2
      if (first > len(text)) return
      if (.not. parse_u64(text(first:), v)) return
      if (v < 0_c_int64_t) return
      if (kind == K_INT .and. v > 2147483647_c_int64_t) return
      ok = .true.
    end select
  end function

  function as_int64(text) result(v)
    character(*), intent(in) :: text
    integer(c_int64_t)       :: v
    integer(c_int64_t) :: mag
    integer            :: first

    first = 1
    if (text(1:1) == '-' .or. text(1:1) == '+') first = 2
    if (.not. parse_u64(text(first:), mag)) mag = 0_c_int64_t
    if (text(1:1) == '-') then
      v = -mag
    else
      v = mag
    end if
  end function

  ! Parses argv into the raw flag values, then validates them.
  ! Accepts -name value, --name value, -name=value and --name=value;
  ! a boolean flag takes no value unless given as -name=true /
  ! -name=false. Returns PARSE_OK, PARSE_HELP (usage printed), or
  ! PARSE_ERROR after printing the first failing rule.
  function parse_flags() result(outcome)
    integer :: outcome
    type(slot_t) :: raw(N_FLAGS)
    character(:), allocatable :: arg, name, value, next
    integer :: i, n, eq, idx, argc

    do i = 1, N_FLAGS
      raw(i)%text = trim(FLAG_DEFAULT(i))
    end do

    outcome = PARSE_ERROR
    argc = command_argument_count()
    i = 1
    do while (i <= argc)
      arg = argument(i)
      if (len(arg) < 2) then
        call err_line("unexpected positional arguments: ["//arg//"]")
        return
      end if
      if (arg(1:1) /= '-') then
        call err_line("unexpected positional arguments: ["//arg//"]")
        return
      end if
      if (arg(2:2) == '-') then
        name = arg(3:)
      else
        name = arg(2:)
      end if
      if (name == "h" .or. name == "help") then
        call usage()
        outcome = PARSE_HELP
        return
      end if
      eq = index(name, "=")
      value = ""
      if (eq > 0) then
        next = name
        value = next(eq + 1:)
        name = next(1:eq - 1)
      end if
      idx = 0
      do n = 1, N_FLAGS
        if (name == trim(FLAG_NAME(n))) then
          idx = n
          exit
        end if
      end do
      if (idx == 0) then
        call err_line("flag provided but not defined: -"//name)
        call usage()
        return
      end if
      if (eq == 0) then
        if (FLAG_KIND(idx) == K_BOOL) then
          value = "true"
        else if (i < argc) then
          i = i + 1
          next = argument(i)
          value = next
        else
          call err_line("flag needs an argument: -"//trim(FLAG_NAME(idx)))
          return
        end if
      end if
      if (.not. value_ok(FLAG_KIND(idx), value)) then
        call err_line('invalid value "'//value//'" for flag -'// &
                      trim(FLAG_NAME(idx)))
        return
      end if
      raw(idx)%text = value
      i = i + 1
    end do

    outcome = validate(raw)
  end function

  ! Values are validated after the whole command line is parsed; the
  ! first failing rule prints its message and stops the run.
  function validate(raw) result(outcome)
    type(slot_t), intent(in) :: raw(N_FLAGS)
    integer                  :: outcome
    character(:), allocatable :: text
    integer                   :: surface

    outcome = PARSE_ERROR
    text = raw(6)%text
    if (.not. parse_duration(text, cfg%duration_ns) &
        .or. cfg%duration_ns <= 0_c_int64_t) then
      call err_line("--duration must be positive, got "//text)
      return
    end if
    cfg%iterations = as_int64(raw(11)%text)
    if (cfg%iterations < 0_c_int64_t) then
      call err_line("--iterations must be >= 0, got "//itoa(cfg%iterations))
      return
    end if
    cfg%workers_requested = int(as_int64(raw(9)%text))
    if (cfg%workers_requested < 1 .or. cfg%workers_requested > MAX_WORKERS) then
      call err_line("--goroutines must be in 1.."//itoa(int(MAX_WORKERS, c_int64_t))// &
                    ", got "//itoa(int(cfg%workers_requested, c_int64_t)))
      return
    end if
    ! Concurrency mode. This binding runs shared-handle: the OpenMP
    ! team's threads call into one Pipeline handle concurrently,
    ! which the shared library permits after construction, so
    ! --goroutines is the thread count verbatim, never clamped.
    cfg%workers = cfg%workers_requested
    if (.not. parse_shape(raw(24)%text, cfg%shape)) then
      call err_line("--shape must be stream | message | stream_one_shot "// &
                    '| both, got "'//raw(24)%text//'"')
      return
    end if
    if (.not. hash_registered(raw(10)%text)) then
      call err_line('--hash "'//raw(10)%text// &
                    '" is not a registered hash primitive')
      return
    end if
    cfg%hash = raw(10)%text
    ! Validated by Init: the C ABI enumerates no MAC names.
    cfg%mac = raw(14)%text
    if (.not. parse_size(raw(20)%text, cfg%payload)) then
      call err_line('--payload-size: invalid size "'//raw(20)%text//'"')
      return
    end if
    if (cfg%payload < 1_c_int64_t) then
      call err_line("--payload-size must be at least 1 byte")
      return
    end if
    if (raw(15)%text == "auto") then
      cfg%memlimit_auto = .true.
      if (cfg%workers <= 3) then
        cfg%memlimit = 1073741824_c_int64_t
      else
        cfg%memlimit = 268435456_c_int64_t
      end if
    else if (.not. parse_size(raw(15)%text, cfg%memlimit)) then
      call err_line('--memlimit: invalid size "'//raw(15)%text//'"')
      return
    end if
    cfg%gogc = int(as_int64(raw(7)%text))
    if (cfg%gogc < 0) then
      call err_line("--gogc must be >= 0, got "// &
                    itoa(int(cfg%gogc, c_int64_t)))
      return
    end if
    if (.not. parse_on_off(raw(18)%text, cfg%parallax)) then
      call err_line('--parallax must be on | off, got "'//raw(18)%text//'"')
      return
    end if
    if (.not. parse_on_off(raw(25)%text, cfg%wrapper)) then
      call err_line('--wrapper must be on | off, got "'//raw(25)%text//'"')
      return
    end if
    cfg%profile = raw(21)%text
    if (len(cfg%profile) > 0) then
      if (.not. profile_surface(cfg%profile, surface)) return
      cfg%shape = narrow_shape(cfg%shape, surface)
    end if
    cfg%key_bits = int(as_int64(raw(13)%text))
    select case (cfg%key_bits)
    case (0, 512, 1024, 2048)
    case default
      call err_line("--key-bits must be 512 | 1024 | 2048 "// &
                    "(or 0 = profile default), got "// &
                    itoa(int(cfg%key_bits, c_int64_t)))
      return
    end select
    cfg%nonce_bits = int(as_int64(raw(17)%text))
    select case (cfg%nonce_bits)
    case (0, 128, 256, 512)
    case default
      call err_line("--nonce-bits must be 128 | 256 | 512 "// &
                    "(or 0 = profile default), got "// &
                    itoa(int(cfg%nonce_bits, c_int64_t)))
      return
    end select
    cfg%blob_mode = int(as_int64(raw(3)%text))
    select case (cfg%blob_mode)
    case (1, 2)
    case default
      call err_line("--blob-mode must be 1 (per-region) | 2 "// &
                    "(per-container), got "// &
                    itoa(int(cfg%blob_mode, c_int64_t)))
      return
    end select
    cfg%barrier_fill = int(as_int64(raw(1)%text))
    select case (cfg%barrier_fill)
    case (0, 1, 2, 4, 8, 16, 32)
    case default
      call err_line("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 "// &
                    "(or 0 = profile default), got "// &
                    itoa(int(cfg%barrier_fill, c_int64_t)))
      return
    end select
    ! Validated by Init: the C ABI enumerates no DRBG names.
    cfg%drbg = raw(5)%text
    if (.not. parse_size(raw(4)%text, cfg%chunk_size)) then
      call err_line('--chunk-size: invalid size "'//raw(4)%text//'"')
      return
    end if
    cfg%gomaxprocs = int(as_int64(raw(8)%text))
    if (cfg%gomaxprocs < 0) then
      call err_line("--gomaxprocs must be > 0 when specified, got "// &
                    itoa(int(cfg%gomaxprocs, c_int64_t)))
      return
    end if
    cfg%rekey_every = as_int64(raw(22)%text)
    if (cfg%rekey_every < 0_c_int64_t) then
      call err_line("--rekey-every must be >= 0, got "//itoa(cfg%rekey_every))
      return
    end if
    cfg%blob_cycle_every = as_int64(raw(2)%text)
    if (cfg%blob_cycle_every < 0_c_int64_t) then
      call err_line("--blob-cycle-every must be >= 0, got "// &
                    itoa(cfg%blob_cycle_every))
      return
    end if
    if (.not. parse_payload_mode(raw(19)%text, cfg%payload_mode)) then
      call err_line("--payload-mode must be fixed | rotating | "// &
                    "pattern-zero | pattern-ff | pattern-ascii, got "// &
                    '"'//raw(19)%text//'"')
      return
    end if
    if (.not. parse_u64(raw(23)%text, cfg%seed)) cfg%seed = 0_c_int64_t
    cfg%json_output = (raw(12)%text == "true")
    cfg%memprofile = raw(16)%text
    outcome = PARSE_OK
  end function

  function parse_on_off(text, flag) result(ok)
    character(*), intent(in) :: text
    logical, intent(out)     :: flag
    logical                  :: ok

    flag = .false.
    ok = .true.
    if (text == "on") then
      flag = .true.
    else if (text == "off") then
      flag = .false.
    else
      ok = .false.
    end if
  end function

  ! Whether name is in the JSON array of strings the binding returns
  ! for the shipped hash registry. Names are restricted to [a-z0-9-],
  ! so a quoted run is one complete name.
  function hash_registered(name) result(found)
    character(*), intent(in) :: name
    logical                  :: found
    character(:), allocatable :: json
    type(itb_error_t)         :: err

    found = .false.
    call itb_hash_names(json, err)
    if (.not. itb_ok(err)) return
    found = index(json, '"'//name//'"') > 0
  end function

  ! Resolves a registered profile to the shape family its record's
  ! mode exposes by reading the record through the binding's lookup:
  ! a mode beginning with "streaming" exposes the stream surfaces,
  ! one beginning with "singlemsg" the message surface, "blob-only"
  ! none.
  function profile_surface(name, surface) result(ok)
    character(*), intent(in) :: name
    integer, intent(out)     :: surface
    logical                  :: ok
    character(:), allocatable :: json
    type(itb_error_t)         :: err
    integer :: at

    surface = SHAPE_STREAM
    ok = .false.
    call itb_lookup(name, json, err)
    if (.not. itb_ok(err)) then
      call err_line('--profile "'//name// &
                    '" is not a registered triple profile')
      return
    end if
    at = index(json, '"mode":"')
    if (at > 0) then
      at = at + 8
      if (json(at:min(at + 8, len(json))) == "streaming") then
        surface = SHAPE_STREAM
        ok = .true.
      else if (json(at:min(at + 8, len(json))) == "singlemsg") then
        surface = SHAPE_MESSAGE
        ok = .true.
      end if
    end if
    if (.not. ok) then
      call err_line('--profile "'//name// &
                    '" carries no cipher surface (blob-only mode)')
    end if
  end function

  ! Applies a --profile's surface to the requested shape: a
  ! message-surface profile forces message; a stream-surface profile
  ! keeps stream or stream_one_shot as requested and turns message or
  ! both into stream.
  function narrow_shape(requested, surface) result(shape)
    integer, intent(in) :: requested, surface
    integer             :: shape

    if (surface == SHAPE_MESSAGE) then
      shape = SHAPE_MESSAGE
      return
    end if
    if (requested == SHAPE_STREAM_ONE_SHOT) then
      shape = SHAPE_STREAM_ONE_SHOT
    else
      shape = SHAPE_STREAM
    end if
  end function

  ! One command-line argument as an exactly-sized string.
  function argument(i) result(s)
    integer, intent(in)       :: i
    character(:), allocatable :: s
    integer :: n

    call get_command_argument(i, length=n)
    if (n <= 0) then
      s = ""
      return
    end if
    allocate (character(len=n) :: s)
    call get_command_argument(i, value=s)
  end function

end module loop_flags

program loop_main
  use, intrinsic :: iso_c_binding
  use omp_lib
  use itb3
  use loop_size
  use loop_state
  use loop_flags
  use loop_payload
  use loop_worker
  use loop_summary
  implicit none

  ! Profiles the shape-based pair is built against when --profile is
  ! empty.
  character(*), parameter :: DEFAULT_STREAM_PROFILE = &
      "streaming-aead-triple-mac-v1"
  character(*), parameter :: DEFAULT_MESSAGE_PROFILE = &
      "singlemsg-triple-mac-v1"

  ! The primitive supplied for the parallax palette and the outer
  ! cipher when a profile leaves them unnamed. AES-CMAC is PRF-grade,
  ! so it is sound outside the Interlocked Barrier, and it is the
  ! closest relative of the AES-based inner primitive whose profiles
  ! need this fill.
  character(*), parameter :: KEYSTREAM_FILL_CIPHER = "aescmac"

  integer            :: outcome, i, code, team
  integer(c_int)     :: prev_int
  integer(c_int64_t) :: warmup_start, elapsed_ns, prev_limit
  logical            :: warmed
  type(itb_error_t)  :: err

  ! The signal dispositions go in before the first byte of output: a
  ! consumer that stops reading can end the run at any line,
  ! including the first, so the restoration cannot wait until the
  ! workers are about to start.
  call install_signals()

  outcome = parse_flags()
  if (outcome == PARSE_HELP) call die(0)
  if (outcome /= PARSE_OK) call die(2)

  ! Runtime shaping. A long run under allocation churn grows the Go
  ! heap inside the shared library without bound unless a soft limit
  ! paces the collector, so a limit is always in force: an explicit
  ! --memlimit is set as given, and auto caps the heap only when the
  ! runtime reports no limit at all (a limit already installed from
  ! the environment is left standing). The GC percentage and
  ! GOMAXPROCS are set only when their flag is non-zero -- a zero
  ! flag skips the setter rather than calling it with zero, because
  ! zero is a real value to the GC-percent setter, and a call would
  ! clobber whatever the environment installed. All of it lands
  ! before any Pipeline exists so the baselines are taken under the
  ! shaped runtime.
  prev_limit = itb_set_memory_limit(-1_c_int64_t)
  if (cfg%memlimit_auto) then
    if (prev_limit == huge(prev_limit)) then
      prev_limit = itb_set_memory_limit(cfg%memlimit)
    end if
  else
    prev_limit = itb_set_memory_limit(cfg%memlimit)
  end if
  cfg%memlimit = itb_set_memory_limit(-1_c_int64_t)
  ! The previous value each setter reports is of no use here: the run
  ! installs its own and never restores them.
  prev_int = 0_c_int
  if (cfg%gogc > 0) prev_int = itb_set_gc_percent(int(cfg%gogc, c_int))
  if (cfg%gomaxprocs > 0) then
    prev_int = itb_set_gomaxprocs(int(cfg%gomaxprocs, c_int))
  end if
  if (prev_int < -1_c_int) call err_line("runtime shaping")

  call log_line("start: duration="//human_duration(cfg%duration_ns)// &
                " iterations="//itoa(cfg%iterations)// &
                " goroutines="//itoa(int(cfg%workers_requested, c_int64_t))// &
                " workers="//itoa(int(cfg%workers, c_int64_t))// &
                " concurrency="//CONCURRENCY// &
                " shape="//shape_name(cfg%shape)// &
                " hash="//cfg%hash//" mac="//cfg%mac// &
                " payload="//human_bytes(cfg%payload)// &
                " memlimit="//human_bytes(cfg%memlimit)// &
                " parallax="//on_off(cfg%parallax)// &
                " wrapper="//on_off(cfg%wrapper))
  call log_line('overrides: profile="'//cfg%profile// &
                '" key-bits='//itoa(int(cfg%key_bits, c_int64_t))// &
                " nonce-bits="//itoa(int(cfg%nonce_bits, c_int64_t))// &
                " chunk-size="//human_bytes(cfg%chunk_size)// &
                " barrier-fill="//itoa(int(cfg%barrier_fill, c_int64_t))// &
                " gomaxprocs="//itoa(int(cfg%gomaxprocs, c_int64_t))// &
                " rekey-every="//itoa(cfg%rekey_every)// &
                " blob-cycle-every="//itoa(cfg%blob_cycle_every)// &
                " payload-mode="//payload_mode_name(cfg%payload_mode)// &
                " seed="//u64toa(cfg%seed)// &
                " json-output="//truth(cfg%json_output)// &
                blob_mode_suffix()//drbg_suffix())
  call log_line("policy: microbatch-tiers="// &
                policy_label("ITB_MICROBATCH_TIERS")// &
                " hashpool-starters="// &
                policy_label("ITB_HASHPOOL_STARTERS"))

  ! Pipeline construction -- one shared handle per exercised shape.
  ! stream and stream_one_shot share the streaming handle.
  if (len(cfg%profile) > 0) then
    stream_profile = cfg%profile
    msg_profile = cfg%profile
  else
    stream_profile = DEFAULT_STREAM_PROFILE
    msg_profile = DEFAULT_MESSAGE_PROFILE
  end if
  if (cfg%shape == SHAPE_STREAM .or. cfg%shape == SHAPE_STREAM_ONE_SHOT &
      .or. cfg%shape == SHAPE_BOTH) then
    call build_pipeline(stream_profile, stream_pipe, stream_blob, stream_active)
    if (.not. stream_active) call die(1)
  end if
  if (cfg%shape == SHAPE_MESSAGE .or. cfg%shape == SHAPE_BOTH) then
    call build_pipeline(msg_profile, msg_pipe, msg_blob, msg_active)
    if (.not. msg_active) call die(1)
  end if

  ! Allocation posture. Per-worker plaintexts are allocated once and
  ! held for the whole run (rotating mode refills them in place per
  ! iteration); the pump accumulators live inside each worker and are
  ! reused across iterations; the message and one-shot outputs are
  ! allocated by the binding per call and released per iteration.
  ! Under the default fixed CSPRNG mode every worker's buffer is
  ! distinct, so cross-worker data crossover is detectable; pattern
  ! modes trade that property for content edge-case coverage.
  do i = 0, cfg%workers - 1
    workers(i)%id = i
    allocate (workers(i)%plaintext(cfg%payload))
    allocate (workers(i)%wire(PUMP_SLICE))
    allocate (workers(i)%plain(PUMP_SLICE))
    workers(i)%seeded = (cfg%seed /= 0_c_int64_t)
    workers(i)%rng = seed_worker(cfg%seed, i)
    if (.not. fill_payload(cfg%payload_mode, workers(i)%seeded, &
                           workers(i)%rng, workers(i)%plaintext)) then
      call err_line("payload fill: csprng")
      call die(1)
    end if
  end do

  if (.not. pool_snapshot_alloc(pool_warmup)) then
    call err_line("pool snapshot alloc failed")
    call die(1)
  end if
  if (.not. pool_snapshot_alloc(pool_steady)) then
    call err_line("pool snapshot alloc failed")
    call die(1)
  end if

  call lock_init()
  active_workers = cfg%workers

  ! Warmup barrier. Every worker runs one iteration and waits; the
  ! clock starts only once all of them have paid their first-call
  ! costs (pool warm-up, lazy kernel dispatch, page faults on the
  ! payload buffers), and the RSS and pool baselines taken here
  ! describe a process that has already run the whole cipher path
  ! once per worker.
  warmup_start = now_ns()
  call omp_set_dynamic(.false.)
  team = 0

  !$omp parallel num_threads(cfg%workers) default(shared) private(warmed)
  !$omp single
  team = omp_get_num_threads()
  !$omp end single
  if (team == cfg%workers) then
    warmed = worker_warmup(omp_get_thread_num())
    !$omp barrier
    !$omp single
    call read_rss(rss_warmup, rss_peak)
    call pool_snapshot_take(pool_warmup)
    call log_line("warmup: "//itoa(int(cfg%workers, c_int64_t))// &
                  " workers x 1 iter completed in "// &
                  human_duration((now_ns() - warmup_start &
                                  + 50000000_c_int64_t) &
                                 / 100000000_c_int64_t &
                                 * 100000000_c_int64_t)// &
                  " (baseline rss="//human_bytes(rss_warmup)//")")
    run_start_ns = now_ns()
    run_finish_ns = run_start_ns
    !$omp end single
    if (warmed) call worker_loop(omp_get_thread_num())
    !$omp critical (finish)
    active_workers = active_workers - 1
    if (active_workers == 0) run_finish_ns = now_ns()
    !$omp end critical (finish)
  end if
  !$omp end parallel

  if (team /= cfg%workers) then
    call err_line("openmp supplied "//itoa(int(team, c_int64_t))// &
                  " of "//itoa(int(cfg%workers, c_int64_t))// &
                  " requested workers")
    call die(1)
  end if
  elapsed_ns = run_finish_ns - run_start_ns
  call read_rss(rss_final, rss_peak)
  call pool_snapshot_take(pool_steady)

  if (len(cfg%memprofile) > 0) then
    call itb_write_heap_profile(cfg%memprofile, err)
    if (itb_ok(err)) then
      call log_line("memprofile: heap profile written to "//cfg%memprofile)
    else
      call err_line("memprofile: "//itb_error_text(err))
    end if
  end if

  code = final_summary(elapsed_ns)

  call lock_destroy()
  if (stream_active) call itb_pipeline_free(stream_pipe)
  if (msg_active) call itb_pipeline_free(msg_pipe)
  call die(code)

contains

  ! The overrides-line entry for --blob-mode, present only when the
  ! value is not the default 1.
  function blob_mode_suffix() result(s)
    character(:), allocatable :: s
    s = ""
    if (cfg%blob_mode /= 1) then
      s = " blob-mode="//itoa(int(cfg%blob_mode, c_int64_t))
    end if
  end function

  ! The overrides-line entry for --drbg, present only when non-empty.
  function drbg_suffix() result(s)
    character(:), allocatable :: s
    s = ""
    if (len(cfg%drbg) > 0) s = " drbg="//cfg%drbg
  end function

  function truth(b) result(s)
    logical, intent(in)       :: b
    character(:), allocatable :: s
    if (b) then
      s = "true"
    else
      s = "false"
    end if
  end function

  ! Integer value of key in a profile JSON record; zero when absent.
  function record_int(json, key) result(v)
    character(*), intent(in) :: json, key
    integer(c_int64_t)       :: v
    character(:), allocatable :: needle
    integer :: at, last, stat

    v = 0_c_int64_t
    needle = '"'//key//'":'
    at = index(json, needle)
    if (at == 0) return
    at = at + len(needle)
    last = at
    do while (last <= len(json))
      if (json(last:last) < '0' .or. json(last:last) > '9') exit
      last = last + 1
    end do
    if (last == at) return
    read (json(at:last - 1), *, iostat=stat) v
    if (stat /= 0) v = 0_c_int64_t
  end function

  ! String value of key in a profile JSON record, or "-" when absent
  ! or empty. Profile record strings are restricted to [a-z0-9-], so
  ! a quoted run is one complete value.
  function record_str(json, key) result(s)
    character(*), intent(in)  :: json, key
    character(:), allocatable :: s
    character(:), allocatable :: needle
    integer :: at, close_at

    needle = '"'//key//'":"'
    at = index(json, needle)
    if (at == 0) then
      s = "-"
      return
    end if
    at = at + len(needle)
    close_at = index(json(at:), '"')
    if (close_at <= 1) then
      s = "-"
      return
    end if
    s = json(at:at + close_at - 2)
  end function

  ! Boolean value of key in a profile JSON record; false when absent.
  function record_bool(json, key) result(b)
    character(*), intent(in) :: json, key
    logical                  :: b
    b = index(json, '"'//key//'":true') > 0
  end function

  ! Prints the construction line with the recipe read back from the
  ! blob the Pipeline handed out, not echoed from the flags: every
  ! construction override is proven to have reached the library by
  ! the value the receiver would see. Record values that are empty (a
  ! No MAC profile's MAC, a mixed profile's single hash) print as
  ! "-".
  subroutine log_pipeline_initialised(profile, blob)
    character(*), intent(in)      :: profile
    integer(c_int8_t), intent(in) :: blob(:)
    character(:), allocatable :: json, line, drbg
    type(itb_error_t)         :: ierr
    integer(c_int64_t)        :: container_mode

    call itb_inspect(blob, json, ierr)
    if (.not. itb_ok(ierr)) then
      call log_line("pipeline initialised: profile="//profile//" blob="// &
                    itoa(int(size(blob, kind=c_int64_t), c_int64_t))// &
                    " bytes (inspect: "//itb_error_text(ierr)//")")
      return
    end if
    drbg = record_str(json, "drbg")
    container_mode = record_int(json, "container_mode")
    line = "pipeline initialised: profile="//profile//" blob="// &
                  itoa(int(size(blob, kind=c_int64_t), c_int64_t))// &
                  " bytes hash="//record_str(json, "hash")// &
                  " key-bits="//itoa(record_int(json, "keybits"))// &
                  " nonce-bits="//itoa(record_int(json, "nonce_bits"))// &
                  " barrier-fill="//itoa(record_int(json, "barrier_fill"))// &
                  " chunk-size="//itoa(record_int(json, "chunk"))// &
                  " mac="//record_str(json, "mac")// &
                  " parallax="//on_off(record_bool(json, "parallax"))// &
                  " wrapper="//on_off(record_bool(json, "wrapper"))
    if (container_mode == 2_c_int64_t) then
      line = line//" container-mode="//itoa(container_mode)
    end if
    if (drbg /= "-") line = line//" drbg="//drbg
    call log_line(line)
  end subroutine

  ! Sets the inner blob's "mode" field of a wrap-layer session blob to
  ! target (1 = per-region, 2 = per-container) in place. The wrap
  ! layer's profile record carries its own "mode" (a string), so the
  ! search starts at the inner blob ("ib"); both shipped modes are one
  ! digit wide, so the blob length does not change and the key
  ! material in blob is never copied. Returns false when the inner
  ! blob or its mode field is not found.
  function edit_inner_blob_mode(blob, target) result(ok)
    integer(c_int8_t), intent(inout) :: blob(:)
    integer, intent(in)              :: target
    logical                          :: ok
    character(*), parameter :: IB_KEY = '"ib":{'
    character(*), parameter :: MODE_KEY = '"mode":'
    integer :: ib, mode, at

    ok = .false.
    ib = find_bytes(blob, 1, IB_KEY)
    if (ib == 0) return
    mode = find_bytes(blob, ib + len(IB_KEY), MODE_KEY)
    if (mode == 0) return
    at = mode + len(MODE_KEY)
    if (at + 1 > size(blob)) return
    if (blob(at) < ichar('1') .or. blob(at) > ichar('2')) return
    if (blob(at + 1) >= ichar('0') .and. blob(at + 1) <= ichar('9')) return
    blob(at) = int(ichar('0') + target, c_int8_t)
    ok = .true.
  end function

  ! Index of the first occurrence of needle in blob at or after from,
  ! or zero when absent. The blob is JSON text held as bytes, so the
  ! search compares byte by byte rather than through a string copy.
  function find_bytes(blob, from, needle) result(at)
    integer(c_int8_t), intent(in) :: blob(:)
    integer, intent(in)           :: from
    character(*), intent(in)      :: needle
    integer                       :: at
    integer :: i, j

    at = 0
    do i = from, size(blob) - len(needle) + 1
      do j = 1, len(needle)
        if (blob(i + j - 1) /= ichar(needle(j:j))) exit
      end do
      if (j > len(needle)) then
        at = i
        return
      end if
    end do
  end function

  ! Folds a keystream primitive into opts for any layer the named
  ! profile leaves unfilled but the operator asked for.
  !
  ! A profile built around a primitive that is safe only inside the
  ! Interlocked Barrier ships with no parallax palette and no outer
  ! cipher: both layers run outside the barrier, where that primitive
  ! would stand bare, so the recipe leaves them unnamed rather than
  ! naming a primitive that must not key them. Engaging either layer
  ! therefore needs a keystream-capable primitive supplied from
  ! outside the recipe; without it construction fails on a palette
  ! below its minimum or an unnamed outer cipher, and the primitive
  ! that most deserves stressing becomes the one that cannot be
  ! stressed with those layers engaged.
  !
  ! Overrides fold into the resolved record the blob carries, so the
  ! receiver rebuilds the same shape from the blob alone.
  !
  ! Fortran-specific. The record is read as JSON text and the two
  ! keys are probed by substring: an absent "palette" or "outer" key
  ! is the unfilled state, since the encoder omits both when unset.
  function fill_keystream_layers(name, opts) result(filled)
    character(*), intent(in)        :: name
    type(itb_opts_t), intent(inout) :: opts
    integer                         :: filled
    character(:), allocatable :: json
    type(itb_error_t)         :: ierr

    filled = -1
    call itb_lookup(name, json, ierr)
    if (.not. itb_ok(ierr)) then
      call err_line('--profile "'//name// &
                    '" is not a registered triple profile')
      return
    end if
    filled = 0
    if (cfg%parallax .and. index(json, '"palette":') == 0) then
      call itb_opts_set(opts, "parallaxPalette", &
                        KEYSTREAM_FILL_CIPHER//","// &
                        KEYSTREAM_FILL_CIPHER//","//KEYSTREAM_FILL_CIPHER)
      if (index(json, '"segment":') == 0) then
        ! A recipe that never carried a palette never carried a
        ! segment size either, and the schedule rejects zero.
        call itb_opts_set(opts, "parallaxSegmentSize", "4093")
      end if
      filled = 1
    end if
    if (cfg%wrapper .and. index(json, '"outer":') == 0) then
      call itb_opts_set(opts, "outerCipher", KEYSTREAM_FILL_CIPHER)
      filled = 1
    end if
  end function

  ! Constructs one Pipeline against profile with every flag-carried
  ! override in the opts string (zero values included -- the shared
  ! library treats zero as "profile default"), then obtains the Init
  ! blob once through save: the binding's init entry does not hand
  ! the blob back, and the bytes are the ones Init produced. Later
  ! blob reopens use the retained blob; save is never called again.
  subroutine build_pipeline(profile, pipe, blob, active)
    character(*), intent(in)                      :: profile
    type(itb_pipeline_t), intent(inout)           :: pipe
    integer(c_int8_t), allocatable, intent(inout) :: blob(:)
    logical, intent(out)                          :: active
    type(itb_opts_t)  :: opts
    type(itb_error_t) :: ierr
    integer           :: filled

    active = .false.
    call itb_opts_set(opts, "innerHash", cfg%hash)
    call itb_opts_set(opts, "macName", cfg%mac)
    call itb_opts_set(opts, "withParallax", truth(cfg%parallax))
    call itb_opts_set(opts, "withWrapper", truth(cfg%wrapper))
    call itb_opts_set(opts, "keyBits", itoa(int(cfg%key_bits, c_int64_t)))
    call itb_opts_set(opts, "nonceBits", itoa(int(cfg%nonce_bits, c_int64_t)))
    call itb_opts_set(opts, "barrierFill", &
                      itoa(int(cfg%barrier_fill, c_int64_t)))
    call itb_opts_set(opts, "drbg", cfg%drbg)
    call itb_opts_set(opts, "chunkSize", itoa(cfg%chunk_size))
    if (len(cfg%profile) > 0) then
      filled = fill_keystream_layers(cfg%profile, opts)
      if (filled < 0) return
      if (filled > 0) then
        call err_line(cfg%profile// &
                      " leaves the requested keystream layers unnamed; "// &
                      KEYSTREAM_FILL_CIPHER//" supplied for them")
      end if
    end if

    call itb_pipeline_init(pipe, profile, opts, ierr)
    if (.not. itb_ok(ierr)) then
      call err_line("Init("//profile//"): "//itb_error_text(ierr))
      return
    end if
    call itb_pipeline_save(pipe, blob, ierr)
    if (.not. itb_ok(ierr)) then
      call err_line("Save("//profile//"): "//itb_error_text(ierr))
      call itb_pipeline_free(pipe)
      return
    end if
    if (cfg%blob_mode == 2) then
      ! The sizing mode is not an Opts knob: the Init blob is edited
      ! and the Pipeline reopened from it, so the retained blob (the
      ! one blob-cycle reopens from) carries the edited mode.
      if (.not. edit_inner_blob_mode(blob, 2)) then
        call err_line("rewrite blob mode: inner blob mode field not found")
        call itb_pipeline_free(pipe)
        return
      end if
      call itb_pipeline_free(pipe)
      call itb_pipeline_load(pipe, blob, ierr)
      if (.not. itb_ok(ierr)) then
        call err_line("reload Mode 2 blob: "//itb_error_text(ierr))
        return
      end if
    end if
    call log_pipeline_initialised(profile, blob)
    active = .true.
  end subroutine

end program loop_main
