! Error-mapping surface: opaque-string relay, unknown profile, closed
! Pipeline, duplicate profile registration (with an 8-entry hashes
! constellation), and the runtime accessors.

program test_errors
  use itb
  use itb_test_helpers
  implicit none

  character(*), parameter :: MIXED = &
      '{"mode":"singlemsg-nomac","width":256,' // &
      '"hashes":["blake3","blake2s","areion256","blake2b256",' // &
      '"chacha20","blake3","blake2s","areion256"],' // &
      '"keybits":1024,"wrapper":false,"parallax":false}'

  type(itb_opts_t)     :: empty, bad_key, neg, bad_hash
  type(itb_pipeline_t) :: pipe, sender, receiver
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: plain(:), wire(:), back(:), blob(:)
  character(:), allocatable :: version, json
  integer :: i

  ! Unknown profile is UnknownProfile with a non-empty diagnostic, on
  ! init and on lookup alike.
  call itb_pipeline_init(pipe, "no-such-profile", empty, err)
  call expect_status(err, ITB_STATUS_UNKNOWN_PROFILE, "unknown profile")
  call check(len(err%message) > 0, "diagnostic non-empty")
  call itb_lookup("no-such-profile", json, err)
  call expect_status(err, ITB_STATUS_UNKNOWN_PROFILE, "lookup unknown profile")

  ! A negative maxWorkers opts value is clamped, not rejected.
  call itb_opts_set(neg, "maxWorkers", "-1")
  call itb_pipeline_init(pipe, "singlemsg-triple-mac-v1", neg, err)
  call expect_ok(err, "init maxWorkers=-1")
  call itb_pipeline_free(pipe)

  ! Typoed opts key (lowercase s) -- Go rejects unknown keys.
  call itb_opts_set(bad_key, "chunksize", "4096")
  call itb_pipeline_init(pipe, "singlemsg-triple-mac-v1", bad_key, err)
  call expect_status(err, ITB_STATUS_BAD_INPUT, "unknown opts key")

  ! Closed Pipeline reports TripleClosed; close is idempotent.
  call itb_pipeline_init(pipe, "singlemsg-triple-mac-v1", empty, err)
  call expect_ok(err, "init")
  call itb_pipeline_close(pipe, err)
  call expect_ok(err, "close")
  call itb_pipeline_close(pipe, err)
  call expect_ok(err, "close idempotent")
  allocate (plain(7))
  plain = byte_of(1)
  call itb_encrypt_message(pipe, plain, wire, err)
  call expect_status(err, ITB_STATUS_TRIPLE_CLOSED, "closed pipeline")
  call itb_pipeline_save(pipe, blob, err)
  call expect_status(err, ITB_STATUS_TRIPLE_CLOSED, "closed save")
  call itb_pipeline_max_workers(pipe, 2, err)
  call expect_status(err, ITB_STATUS_TRIPLE_CLOSED, "closed max_workers")
  call itb_pipeline_free(pipe)

  ! Register an 8-entry width-256 hashes constellation, layers off,
  ! from a profile JSON record; the registered profile round-trips
  ! and reads back; a duplicate name is a distinct status.
  call itb_register("fortran-binding-test-mixed", MIXED, err)
  call expect_ok(err, "register profile")
  call itb_lookup("fortran-binding-test-mixed", json, err)
  call expect_ok(err, "lookup registered")
  call check(index(json, '"name":"fortran-binding-test-mixed"') > 0, &
      "lookup carries the name")
  call check(index(json, '"hashes":["blake3","blake2s"') > 0, &
      "lookup carries the hashes")

  ! A non-empty name inside the record must equal the argument.
  call itb_register("fortran-binding-test-mismatch", &
      '{"name":"other","mode":"singlemsg-nomac","width":512,' // &
      '"hash":"areion512","keybits":1024,"wrapper":false,"parallax":false}', &
      err)
  call expect_status(err, ITB_STATUS_BAD_INPUT, "name mismatch")

  call itb_pipeline_init(sender, "fortran-binding-test-mixed", empty, err)
  call expect_ok(err, "init registered profile")
  call load_from(sender, receiver, err)
  call expect_ok(err, "load registered profile")
  deallocate (plain)
  allocate (plain(14))
  do i = 1, size(plain)
    plain(i) = byte_of(80 + i)
  end do
  call itb_encrypt_message(sender, plain, wire, err)
  call expect_ok(err, "encrypt registered profile")
  call itb_decrypt_message(receiver, wire, back, err)
  call expect_ok(err, "decrypt registered profile")
  call check_bytes_equal(back, plain, "registered profile round trip")
  call itb_pipeline_free(receiver)
  call itb_pipeline_free(sender)

  call itb_register("fortran-binding-test-mixed", MIXED, err)
  call expect_status(err, ITB_STATUS_PROFILE_EXISTS, "duplicate profile")

  ! An unknown inner-hash name is relayed to Go and rejected there --
  ! the binding performs no name validation of its own.
  call itb_opts_set(bad_hash, "innerHash", "no-such-hash")
  call itb_pipeline_init(pipe, "singlemsg-triple-mac-v1", bad_hash, err)
  call check(err%status /= ITB_STATUS_OK, "opaque name relay rejected")

  ! Runtime accessors respond.
  call itb_version(version, err)
  call expect_ok(err, "version")
  call check(len(version) > 0, "version non-empty")

  call test_done("test_errors")
end program
