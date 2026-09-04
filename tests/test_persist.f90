! Persistence surface: save / save_f / load / load_f round trips,
! inspect, lookup / profiles, max_workers.

program test_persist
  use itb
  use itb_test_helpers
  implicit none

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: blob(:), again(:), plain(:), wire(:), back(:)
  integer(c_int8_t) :: perm(32), wrap(32)
  character(:), allocatable :: inspected, looked, names
  character(len=64) :: path
  integer :: i, unit, stat

  allocate (plain(15))
  do i = 1, size(plain)
    plain(i) = byte_of(96 + i)
  end do

  call itb_pipeline_init(sender, "singlemsg-triple-mac-v1", opts, err)
  call expect_ok(err, "init")

  ! save -> load; save is stable; load retains the bytes.
  call itb_pipeline_save(sender, blob, err)
  call expect_ok(err, "save")
  call itb_pipeline_save(sender, again, err)
  call expect_ok(err, "save again")
  call check_bytes_equal(again, blob, "save is stable")
  call itb_pipeline_load(receiver, blob, err)
  call expect_ok(err, "load")
  call round_trip("in-memory")
  call itb_pipeline_save(receiver, again, err)
  call expect_ok(err, "save receiver")
  call check_bytes_equal(again, blob, "load retains the blob bytes")
  call itb_pipeline_free(receiver)

  ! load with master overrides == sender rekey.
  perm = byte_of(49)
  wrap = byte_of(50)
  call itb_pipeline_load(receiver, blob, err, perm_master=perm, wrap_master=wrap)
  call expect_ok(err, "load with masters")
  call itb_pipeline_save(receiver, again, err)
  call expect_ok(err, "save rotated")
  call check(size(again) /= size(blob) .or. .not. all(again == blob), &
      "master overrides rotate the blob")
  call itb_pipeline_rekey(sender, perm, wrap, err)
  call expect_ok(err, "rekey")
  call round_trip("overrides")
  call itb_pipeline_free(receiver)

  ! inspect == lookup for a shipped profile; garbage is BAD_INPUT.
  call itb_inspect(blob, inspected, err)
  call expect_ok(err, "inspect")
  call itb_lookup("singlemsg-triple-mac-v1", looked, err)
  call expect_ok(err, "lookup")
  call check(inspected == looked, "inspect / lookup mismatch")
  call check(index(inspected, '"name":"singlemsg-triple-mac-v1"') > 0, &
      "inspect carries the name")
  call check(index(inspected, '"mode":"singlemsg-mac"') > 0, &
      "inspect carries the mode")
  call itb_inspect(plain, inspected, err)
  call expect_status(err, ITB_STATUS_BAD_INPUT, "inspect garbage")

  ! profiles lists the shipped catalogue as a JSON array.
  call itb_profiles(names, err)
  call expect_ok(err, "profiles")
  call check(len(names) > 0, "profiles non-empty")
  call check(names(1:1) == "[", "profiles is a JSON array")
  call check(index(names, '"singlemsg-triple-mac-v1"') > 0, &
      "profiles lists the shipped profile")

  ! save_f -> load_f on a temp file; a missing file is BAD_INPUT.
  path = "/tmp/itb-fortran-persist.blob"
  call itb_pipeline_save_f(sender, trim(path), err)
  call expect_ok(err, "save_f")
  call itb_pipeline_load_f(receiver, trim(path), err)
  call expect_ok(err, "load_f")
  call round_trip("on-disk")
  call itb_pipeline_free(receiver)
  open (newunit=unit, file=trim(path), status="old", iostat=stat)
  if (stat == 0) close (unit, status="delete")
  call itb_pipeline_load_f(receiver, trim(path), err)
  call expect_status(err, ITB_STATUS_BAD_INPUT, "load_f missing")

  ! max_workers clamps and round-trips.
  call itb_pipeline_max_workers(sender, 2, err)
  call expect_ok(err, "max_workers 2")
  call itb_pipeline_max_workers(sender, -1, err)
  call expect_ok(err, "max_workers -1")
  call itb_pipeline_max_workers(sender, 100000, err)
  call expect_ok(err, "max_workers 100000")
  call load_from(sender, receiver, err)
  call expect_ok(err, "load")
  call itb_pipeline_max_workers(receiver, 1, err)
  call expect_ok(err, "max_workers receiver")
  call round_trip("workers")
  call itb_pipeline_free(receiver)
  call itb_pipeline_free(sender)
  call test_done("test_persist")

contains

  subroutine round_trip(label)
    character(*), intent(in) :: label
    call itb_encrypt_message(sender, plain, wire, err)
    call expect_ok(err, label//" encrypt")
    call itb_decrypt_message(receiver, wire, back, err)
    call expect_ok(err, label//" decrypt")
    call check_bytes_equal(back, plain, label//" round trip")
  end subroutine

end program
