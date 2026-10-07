! Persistence surface: save / save_f / load / load_f round trips,
! inspect, lookup / profiles, max_workers.

program test_persist
  use itb3
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

  ! inspect carries the registry recipe plus the blob-only nonce_bits
  ! / barrier_fill inspection fields; lookup returns just the recipe.
  ! Garbage is BAD_INPUT.
  call itb_inspect(blob, inspected, err)
  call expect_ok(err, "inspect")
  call itb_lookup("singlemsg-triple-mac-v1", looked, err)
  call expect_ok(err, "lookup")
  call check(index(inspected, '"name":"singlemsg-triple-mac-v1"') > 0, &
      "inspect carries the name")
  call check(index(inspected, '"mode":"singlemsg-mac"') > 0, &
      "inspect carries the mode")
  call check(index(looked, '"name":"singlemsg-triple-mac-v1"') > 0, &
      "lookup carries the name")
  call check(index(inspected, '"nonce_bits":') > 0, &
      "inspect carries the inspection-only nonce_bits field")
  call check(index(inspected, '"barrier_fill":') > 0, &
      "inspect carries the inspection-only barrier_fill field")
  call check(index(looked, '"nonce_bits":') == 0, &
      "lookup does not carry the inspection-only nonce_bits field")
  call check(index(looked, '"barrier_fill":') == 0, &
      "lookup does not carry the inspection-only barrier_fill field")
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
  call drbg_cases()
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

  ! The drbg recipe key: an init under each named fill primitive
  ! round-trips through a loaded blob and is reported by inspect; the
  ! default leaves the key out of inspect and lookup; an inspected
  ! record re-registers under a new name and keeps the key. The
  ! register payload drops the name and the inspection-only
  ! nonce_bits / barrier_fill / container_mode keys, which sit
  ! contiguously between keybits and drbg.
  subroutine drbg_cases()
    character(len=9), parameter :: drbg_names(2) = [character(len=9) :: &
        "csprng", "aesitb128"]
    type(itb_opts_t)     :: dopts, none
    type(itb_pipeline_t) :: dsend, drecv
    integer(c_int8_t), allocatable :: dblob(:), dwire(:), dback(:)
    character(:), allocatable :: djson, dlooked, payload
    integer :: k, p_mode, p_cut, p_drbg

    do k = 1, size(drbg_names)
      dopts = itb_opts_t()
      call itb_opts_set(dopts, "drbg", trim(drbg_names(k)))
      call itb_pipeline_init(dsend, "singlemsg-triple-mac-v1", dopts, err)
      call expect_ok(err, "init drbg="//trim(drbg_names(k)))
      call itb_pipeline_save(dsend, dblob, err)
      call expect_ok(err, "save drbg")
      call itb_pipeline_load(drecv, dblob, err)
      call expect_ok(err, "load drbg")
      call itb_encrypt_message(dsend, plain, dwire, err)
      call expect_ok(err, "drbg encrypt")
      call itb_decrypt_message(drecv, dwire, dback, err)
      call expect_ok(err, "drbg decrypt")
      call check_bytes_equal(dback, plain, "drbg round trip")
      call itb_encrypt_message(drecv, plain, dwire, err)
      call expect_ok(err, "drbg reverse encrypt")
      call itb_decrypt_message(dsend, dwire, dback, err)
      call expect_ok(err, "drbg reverse decrypt")
      call check_bytes_equal(dback, plain, "drbg reverse round trip")

      call itb_inspect(dblob, djson, err)
      call expect_ok(err, "inspect drbg")
      call check(index(djson, '"drbg":"'//trim(drbg_names(k))//'"') > 0, &
          "inspect carries the drbg key")

      if (trim(drbg_names(k)) == "csprng") then
        p_mode = index(djson, '"mode"')
        p_cut = index(djson, '"nonce_bits"')
        p_drbg = index(djson, '"drbg"')
        call check(p_mode > 0 .and. p_cut > p_mode .and. p_drbg > p_cut, &
            "inspect key order for the register payload")
        payload = "{"//djson(p_mode:p_cut - 1)//djson(p_drbg:)
        call itb_register("fortran-binding-test-drbg-copy", payload, err)
        call expect_ok(err, "register drbg copy")
        call itb_lookup("fortran-binding-test-drbg-copy", dlooked, err)
        call expect_ok(err, "lookup drbg copy")
        call check(index(dlooked, '"drbg":"csprng"') > 0, &
            "lookup keeps the drbg key")
      end if
      call itb_pipeline_free(drecv)
      call itb_pipeline_free(dsend)
    end do

    call itb_pipeline_init(dsend, "singlemsg-triple-mac-v1", none, err)
    call expect_ok(err, "init default drbg")
    call itb_pipeline_save(dsend, dblob, err)
    call expect_ok(err, "save default drbg")
    call itb_inspect(dblob, djson, err)
    call expect_ok(err, "inspect default drbg")
    call check(index(djson, '"drbg"') == 0, "default inspect omits drbg")
    call itb_lookup("singlemsg-triple-mac-v1", dlooked, err)
    call expect_ok(err, "lookup shipped")
    call check(index(dlooked, '"drbg"') == 0, "shipped lookup omits drbg")
    call itb_pipeline_free(dsend)
  end subroutine

end program
