! Shared declarations of the loop stress harness: the resolved
! configuration, the per-worker state, the run state every worker
! shares, the reader / writer lock that keeps iterations clear of
! handle mutation, and the line-at-a-time output primitives.
!
! Fortran-specific. A module is how Fortran shares declarations, and
! its compile order is its dependency order, so the state the worker,
! ops and summary units all reach lives here rather than in any one
! of them. A language with mutually-visible modules folds these into
! the units that own them.

module loop_state
  use, intrinsic :: iso_c_binding
  use omp_lib
  use itb3
  use loop_size, only: itoa
  implicit none
  private

  public :: MAX_WORKERS, PUMP_SLICE, CONCURRENCY
  public :: SHAPE_STREAM, SHAPE_MESSAGE, SHAPE_STREAM_ONE_SHOT, SHAPE_BOTH
  public :: PAYLOAD_FIXED, PAYLOAD_ROTATING, PAYLOAD_PATTERN_ZERO
  public :: PAYLOAD_PATTERN_FF, PAYLOAD_PATTERN_ASCII
  public :: SIG_INT, SIG_TERM, SIG_PIPE
  public :: config_t, worker_t
  public :: cfg, workers
  public :: stream_pipe, msg_pipe, stream_active, msg_active
  public :: stream_profile, msg_profile, stream_blob, msg_blob
  public :: rekeys, blob_cycles, stop_requested
  public :: run_start_ns, run_finish_ns, active_workers
  public :: rss_warmup, rss_peak, rss_final, pool_warmup, pool_steady
  public :: lock_init, lock_destroy, rd_lock, rd_unlock, wr_lock, wr_unlock
  public :: emit, log_line, err_line, die, worker_fail, install_signals
  public :: on_off, policy_label, env_value, worker_tag
  public :: c_write, c_signal, c_getrandom, c_exit, c_sched_yield

  ! --goroutines ceiling; the harness targets modest hosts and each
  ! worker pins payload-sized buffers for the whole run.
  integer, parameter :: MAX_WORKERS = 10

  ! Largest slice fed to a stream session per write; the drain after
  ! every write uses the same bound.
  integer, parameter :: PUMP_SLICE = 1048576

  ! The concurrency mode this binding implements, as the summary
  ! reports it (shared-handle / independent-handles / single).
  character(*), parameter :: CONCURRENCY = "shared-handle"

  ! Cipher surfaces the --shape flag selects.
  integer, parameter :: SHAPE_STREAM = 0          ! session pump
  integer, parameter :: SHAPE_MESSAGE = 1         ! Single Message
  integer, parameter :: SHAPE_STREAM_ONE_SHOT = 2 ! one-shot stream
  integer, parameter :: SHAPE_BOTH = 3            ! all three, rotating

  ! Plaintext content policies the --payload-mode flag selects.
  integer, parameter :: PAYLOAD_FIXED = 0
  integer, parameter :: PAYLOAD_ROTATING = 1
  integer, parameter :: PAYLOAD_PATTERN_ZERO = 2
  integer, parameter :: PAYLOAD_PATTERN_FF = 3
  integer, parameter :: PAYLOAD_PATTERN_ASCII = 4

  integer(c_int), parameter :: SIG_INT = 2
  integer(c_int), parameter :: SIG_TERM = 15
  integer(c_int), parameter :: SIG_PIPE = 13

  ! The resolved command line.
  type :: config_t
    integer(c_int64_t)        :: duration_ns = 0_c_int64_t
    integer(c_int64_t)        :: iterations = 0_c_int64_t
    integer                   :: workers_requested = 0
    integer                   :: workers = 0
    integer                   :: shape = SHAPE_STREAM
    character(:), allocatable :: hash
    character(:), allocatable :: mac
    integer(c_int64_t)        :: payload = 0_c_int64_t
    integer(c_int64_t)        :: memlimit = 0_c_int64_t
    logical                   :: memlimit_auto = .false.
    integer                   :: gogc = 0
    logical                   :: parallax = .true.
    logical                   :: wrapper = .true.
    character(:), allocatable :: profile
    integer                   :: key_bits = 0
    integer                   :: nonce_bits = 0
    integer                   :: blob_mode = 1 ! 1 = per-region, 2 = per-container
    integer(c_int64_t)        :: chunk_size = 0_c_int64_t
    integer                   :: barrier_fill = 0
    character(:), allocatable :: drbg ! empty = profile default
    integer                   :: gomaxprocs = 0
    integer(c_int64_t)        :: rekey_every = 0_c_int64_t
    integer(c_int64_t)        :: blob_cycle_every = 0_c_int64_t
    integer                   :: payload_mode = PAYLOAD_FIXED
    integer(c_int64_t)        :: seed = 0_c_int64_t
    logical                   :: json_output = .false.
    character(:), allocatable :: memprofile
  end type

  ! One worker's private state: its plaintext, its reusable pump
  ! accumulators, its generator, its counters, and the error it
  ! stopped on.
  type :: worker_t
    integer                        :: id = 0
    integer(c_int8_t), allocatable :: plaintext(:)
    logical                        :: seeded = .false.
    integer(c_int64_t)             :: rng = 0_c_int64_t
    integer(c_int8_t), allocatable :: wire(:)
    integer(c_int64_t)             :: wire_len = 0_c_int64_t
    integer(c_int8_t), allocatable :: plain(:)
    integer(c_int64_t)             :: plain_len = 0_c_int64_t
    integer(c_int64_t)             :: iters = 0_c_int64_t
    integer(c_int64_t)             :: bytes_enc = 0_c_int64_t
    integer(c_int64_t)             :: bytes_dec = 0_c_int64_t
    integer(c_int64_t)             :: nanos_enc = 0_c_int64_t
    integer(c_int64_t)             :: nanos_dec = 0_c_int64_t
    logical                        :: failed = .false.
    character(:), allocatable      :: error
  end type

  type(config_t), save :: cfg
  type(worker_t), save :: workers(0:MAX_WORKERS - 1)

  ! The Pipeline handles every worker calls into, and the blobs Init
  ! handed out, replaced by every rekey. Guarded by the lock below.
  type(itb_pipeline_t), save     :: stream_pipe, msg_pipe
  logical, save                  :: stream_active = .false.
  logical, save                  :: msg_active = .false.
  character(:), allocatable, save :: stream_profile, msg_profile
  integer(c_int8_t), allocatable, save :: stream_blob(:), msg_blob(:)

  integer(c_int64_t), save :: rekeys = 0_c_int64_t
  integer(c_int64_t), save :: blob_cycles = 0_c_int64_t

  ! Set by the deadline check, by a signal, or by a failing worker;
  ! read by every worker before it starts an iteration.
  logical, volatile, save :: stop_requested = .false.

  integer(c_int64_t), save :: run_start_ns = 0_c_int64_t
  integer(c_int64_t), save :: run_finish_ns = 0_c_int64_t
  integer, save            :: active_workers = 0

  ! Baselines taken after the warmup barrier and at shutdown.
  integer(c_int64_t), save :: rss_warmup = 0_c_int64_t
  integer(c_int64_t), save :: rss_peak = 0_c_int64_t
  integer(c_int64_t), save :: rss_final = 0_c_int64_t
  integer(c_int64_t), allocatable, save :: pool_warmup(:), pool_steady(:)

  ! Handle mutation. Iterations hold the read side for their whole
  ! encrypt -> decrypt -> compare; rekey and blob reopen take the
  ! write side, so no cipher call is in flight while a handle's
  ! keying changes or the handle itself is swapped, and no encrypt is
  ! separated from its decrypt by either.
  !
  ! Fortran-specific. OpenMP offers a mutex and no reader / writer
  ! lock, and a mutex over every iteration would serialise the
  ! workers while still reporting an even split, which is the defect
  ! this harness exists to surface. The counter pair below is the
  ! reader / writer lock built on the mutex OpenMP does offer: a
  ! raised writer flag bars new readers, so a waiting writer cannot
  ! be starved, and both waits yield the CPU rather than spinning on
  ! it. Maintenance is the only writer and runs rarely.
  integer(omp_lock_kind), save :: lock_gate
  integer, save                :: lock_readers = 0
  logical, save                :: lock_writer = .false.

  interface

    function c_write(fd, buf, n) bind(C, name="write") result(r)
      import
      integer(c_int), value    :: fd
      type(c_ptr), value       :: buf
      integer(c_size_t), value :: n
      integer(c_intptr_t)      :: r
    end function

    function c_signal(sig, handler) bind(C, name="signal") result(prev)
      import
      integer(c_int), value :: sig
      type(c_funptr), value :: handler
      type(c_funptr)        :: prev
    end function

    function c_getrandom(buf, n, flags) bind(C, name="getrandom") result(r)
      import
      type(c_ptr), value       :: buf
      integer(c_size_t), value :: n
      integer(c_int), value    :: flags
      integer(c_intptr_t)      :: r
    end function

    subroutine c_exit(code) bind(C, name="exit")
      import
      integer(c_int), value :: code
    end subroutine

    function c_sched_yield() bind(C, name="sched_yield") result(r)
      import
      integer(c_int) :: r
    end function

  end interface

contains

  ! A line and its newline leave in one write. Workers log
  ! concurrently during maintenance, so the text and the terminator
  ! are assembled first and handed to a single write call; a split
  ! pair would let another worker's line land between them.
  !
  ! Fortran-specific. The list-directed and formatted output
  ! statements write through libgfortran's own unit buffers, which
  ! neither guarantee one record per system call nor fail promptly
  ! when the consumer goes away, so every byte this utility emits
  ! goes through the raw descriptor instead.
  subroutine emit(fd, text)
    integer(c_int), intent(in) :: fd
    character(*), intent(in)   :: text
    character(kind=c_char), allocatable, target :: buf(:)
    integer             :: i, n
    integer(c_intptr_t) :: off, w

    n = len(text)
    allocate (buf(n + 1))
    do i = 1, n
      buf(i) = text(i:i)
    end do
    buf(n + 1) = c_new_line
    off = 0_c_intptr_t
    do while (off < int(n + 1, c_intptr_t))
      w = c_write(fd, c_loc(buf(int(off) + 1)), &
                  int(n + 1 - int(off), c_size_t))
      if (w <= 0_c_intptr_t) exit
      off = off + w
    end do
    deallocate (buf)
  end subroutine

  ! One prefixed status line on stdout.
  subroutine log_line(text)
    character(*), intent(in) :: text
    call emit(1_c_int, "[loop] "//text)
  end subroutine

  ! One prefixed diagnostic on stderr.
  subroutine err_line(text)
    character(*), intent(in) :: text
    call emit(2_c_int, "loop: "//text)
  end subroutine

  ! Fortran-specific. `stop n` and `error stop` print the code to
  ! stderr, which the output contract has no line for, so every exit
  ! leaves through the C library instead.
  subroutine die(code)
    integer, intent(in) :: code
    call c_exit(int(code, c_int))
  end subroutine

  ! Records the worker's error text (first error wins) and requests a
  ! stop of the whole run.
  subroutine worker_fail(w, text)
    type(worker_t), intent(inout) :: w
    character(*), intent(in)      :: text

    if (.not. w%failed) then
      w%error = text
      w%failed = .true.
    end if
    stop_requested = .true.
  end subroutine

  function on_off(b) result(s)
    logical, intent(in)       :: b
    character(:), allocatable :: s
    if (b) then
      s = "on"
    else
      s = "off"
    end if
  end function

  ! The value of an environment variable, or the empty string when it
  ! is unset.
  function env_value(name) result(s)
    character(*), intent(in)  :: name
    character(:), allocatable :: s
    integer :: n, stat

    call get_environment_variable(name, length=n, status=stat)
    if (stat /= 0 .or. n <= 0) then
      s = ""
      return
    end if
    allocate (character(len=n) :: s)
    call get_environment_variable(name, value=s, status=stat)
    if (stat /= 0) s = ""
  end function

  ! Renders an encoder policy env value for the summary: the raw
  ! string when set, "default" when the shipped ladder applies.
  function policy_label(name) result(s)
    character(*), intent(in)  :: name
    character(:), allocatable :: s
    character(:), allocatable :: raw

    raw = env_value(name)
    if (len_trim(raw) == 0) then
      s = "default"
      return
    end if
    s = raw(verify(raw, " "//achar(9)):)
  end function

  ! Graceful stop. SIGINT / SIGTERM set the stop flag every worker
  ! checks before it starts an iteration, so a signal interrupts
  ! nothing mid-call -- the in-flight encrypt / decrypt / compare
  ! completes, the worker returns, and the partial summary prints
  ! with the verdict the completed iterations earned.
  !
  ! SIGPIPE is restored to its default disposition in the same place.
  ! A consumer that stops reading ends the run: the utility dies from
  ! the signal with exit 141 and prints nothing further, which is
  ! what anyone piping into head or less expects. The libitb3 load
  ! has installed a handler of its own by the time this runs, so the
  ! restoration is an explicit step rather than something inherited.
  subroutine install_signals()
    type(c_funptr) :: prev

    prev = c_signal(SIG_INT, c_funloc(on_signal))
    prev = c_signal(SIG_TERM, c_funloc(on_signal))
    prev = c_signal(SIG_PIPE, c_null_funptr)
    ! The previous dispositions are of no use here: the run installs
    ! its own and never restores them.
    if (c_associated(prev)) prev = c_null_funptr
  end subroutine

  subroutine on_signal(sig) bind(C)
    integer(c_int), value :: sig

    if (sig /= 0_c_int) stop_requested = .true.
  end subroutine

  subroutine lock_init()
    call omp_init_lock(lock_gate)
    lock_readers = 0
    lock_writer = .false.
  end subroutine

  subroutine lock_destroy()
    call omp_destroy_lock(lock_gate)
  end subroutine

  subroutine rd_lock()
    integer(c_int) :: ignored

    do
      call omp_set_lock(lock_gate)
      if (.not. lock_writer) then
        lock_readers = lock_readers + 1
        call omp_unset_lock(lock_gate)
        return
      end if
      call omp_unset_lock(lock_gate)
      ignored = c_sched_yield()
    end do
  end subroutine

  subroutine rd_unlock()
    call omp_set_lock(lock_gate)
    lock_readers = lock_readers - 1
    call omp_unset_lock(lock_gate)
  end subroutine

  subroutine wr_lock()
    integer(c_int) :: ignored

    do
      call omp_set_lock(lock_gate)
      if (.not. lock_writer) then
        lock_writer = .true.
        call omp_unset_lock(lock_gate)
        exit
      end if
      call omp_unset_lock(lock_gate)
      ignored = c_sched_yield()
    end do
    do
      call omp_set_lock(lock_gate)
      if (lock_readers == 0) then
        call omp_unset_lock(lock_gate)
        return
      end if
      call omp_unset_lock(lock_gate)
      ignored = c_sched_yield()
    end do
  end subroutine

  subroutine wr_unlock()
    call omp_set_lock(lock_gate)
    lock_writer = .false.
    call omp_unset_lock(lock_gate)
  end subroutine

  ! "g<id> iter <n>" -- the prefix every worker-error text opens with.
  function worker_tag(id, iter) result(s)
    integer, intent(in)            :: id
    integer(c_int64_t), intent(in) :: iter
    character(:), allocatable      :: s
    s = "g"//itoa(int(id, c_int64_t))//" iter "//itoa(iter)
  end function

end module loop_state
