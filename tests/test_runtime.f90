! Go runtime knobs and the hash-registry enumeration: the setters
! report the previous value and the query forms read back what was
! installed, the heap profile reaches the file system, the pool
! counters come back at the length the library reports and in the
! layout it documents, and the registry lists the names
! itb_pipeline_init accepts for "innerHash".

program test_runtime
  use, intrinsic :: iso_fortran_env, only: int64
  use itb3
  use itb_test_helpers
  implicit none

  type(itb_error_t) :: err
  character(:), allocatable :: json
  integer(c_int64_t), allocatable :: slots(:)
  integer(c_int64_t), allocatable :: narrow(:)
  integer(c_int)     :: prev_procs, procs
  integer(c_int64_t) :: prev_limit
  integer            :: n, written, tiers, path_len
  character(len=256) :: prof_path
  logical            :: present_on_disk
  integer            :: prof_size

  ! ---- GOMAXPROCS ---------------------------------------------------
  prev_procs = itb_set_gomaxprocs(0_c_int)
  call check(prev_procs > 0, "gomaxprocs query returns a positive value")
  prev_procs = itb_set_gomaxprocs(2_c_int)
  call check(prev_procs > 0, "gomaxprocs setter reports the previous value")
  procs = itb_set_gomaxprocs(0_c_int)
  call check(procs == 2_c_int, "gomaxprocs query reads back the value set")
  prev_procs = itb_set_gomaxprocs(prev_procs)

  ! ---- heap limit, for the symmetry the query forms share -----------
  prev_limit = itb_set_memory_limit(-1_c_int64_t)
  call check(prev_limit /= 0_c_int64_t, "memory limit query is non-zero")

  ! ---- pool counters ------------------------------------------------
  n = itb_pool_stats_len()
  call check(n > 0, "pool stats length is positive")
  allocate (slots(n))
  call itb_pool_stats(slots, written, err)
  call expect_ok(err, "pool_stats")
  call check(written == n, "pool stats fills every slot the length reports")
  tiers = int(slots(1))
  call check(tiers > 0, "slot 1 carries a positive tier count")
  call check(1 + 5 * tiers + 8 == n, "length is 1 + 5*T + 8")

  ! A destination shorter than the reported length is refused, with
  ! the requirement reported back through the written count.
  allocate (narrow(1))
  call itb_pool_stats(narrow, written, err)
  call expect_status(err, ITB_STATUS_BUFFER_TOO_SMALL, "pool_stats short buffer")
  call check(written == n, "short buffer reports the required slot count")

  ! The counters are monotonic totals since library load, so a second
  ! snapshot after a round trip never goes backwards.
  block
    integer(c_int64_t), allocatable :: later(:)
    integer :: i
    type(itb_opts_t)     :: opts
    type(itb_pipeline_t) :: pipe
    integer(c_int8_t), allocatable :: plain(:), wire(:), back(:)

    call itb_pipeline_init(pipe, "singlemsg-triple-nomac-v1", opts, err)
    call expect_ok(err, "init for pool traffic")
    allocate (plain(4096))
    call fill_mod(plain, 251)
    call itb_encrypt_message(pipe, plain, wire, err)
    call expect_ok(err, "encrypt for pool traffic")
    call itb_decrypt_message(pipe, wire, back, err)
    call expect_ok(err, "decrypt for pool traffic")
    call check_bytes_equal(back, plain, "pool traffic round trip")
    call itb_pipeline_free(pipe)

    allocate (later(n))
    call itb_pool_stats(later, written, err)
    call expect_ok(err, "pool_stats again")
    do i = 1, n
      call check(later(i) >= slots(i), "pool counters never decrease")
    end do
    call check(later(3) > slots(3), "tier 0 checkouts advanced")
  end block

  ! ---- heap profile -------------------------------------------------
  call get_environment_variable("TMPDIR", value=prof_path, length=path_len)
  if (path_len <= 0) then
    prof_path = "/tmp"
  end if
  prof_path = trim(prof_path)//"/itb_fortran_heap.prof"
  call itb_write_heap_profile(trim(prof_path), err)
  call expect_ok(err, "write_heap_profile")
  inquire (file=trim(prof_path), exist=present_on_disk, size=prof_size)
  call check(present_on_disk, "heap profile exists")
  call check(prof_size > 0, "heap profile is non-empty")
  open (newunit=n, file=trim(prof_path), status="old")
  close (n, status="delete")

  ! An empty path with no ITB_MEMPROFILE in the environment is
  ! rejected rather than written somewhere arbitrary.
  if (len_trim(env_or_empty("ITB_MEMPROFILE")) == 0) then
    call itb_write_heap_profile("", err)
    call expect_status(err, ITB_STATUS_BAD_INPUT, "write_heap_profile empty path")
  end if

  ! ---- hash registry ------------------------------------------------
  call itb_hash_names(json, err)
  call expect_ok(err, "hash_names")
  call check(len(json) > 2, "hash registry JSON is non-empty")
  call check(json(1:1) == "[", "hash registry is a JSON array")
  call check(index(json, '"areion512"') > 0, "registry lists areion512")
  call check(index(json, '"aesitb128"') > 0, "registry lists aesitb128")
  call check(index(json, '"nope"') == 0, "registry does not list a made-up name")

  call test_done("test_runtime")

contains

  function env_or_empty(name) result(s)
    character(*), intent(in)  :: name
    character(:), allocatable :: s
    integer :: n_env, stat

    call get_environment_variable(name, length=n_env, status=stat)
    if (stat /= 0 .or. n_env <= 0) then
      s = ""
      return
    end if
    allocate (character(len=n_env) :: s)
    call get_environment_variable(name, value=s, status=stat)
    if (stat /= 0) s = ""
  end function

end program
