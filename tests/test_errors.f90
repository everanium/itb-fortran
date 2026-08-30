! Error-mapping surface: opaque-string relay, closed Pipeline,
! duplicate profile registration (with an 8-entry innerHashes
! constellation), and the runtime accessors.

program test_errors
  use itb
  use itb_test_helpers
  implicit none

  type(itb_opts_t)     :: empty, bad_key, mixed, bad_hash
  type(itb_pipeline_t) :: pipe, sender, receiver
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: plain(:), wire(:), back(:)
  character(:), allocatable :: version, name
  integer :: i

  ! Unknown profile is BadInput with a non-empty diagnostic.
  call itb_pipeline_init(pipe, "no-such-profile", empty, err)
  call expect_status(err, ITB_STATUS_BAD_INPUT, "unknown profile")
  call check(len(err%message) > 0, "diagnostic non-empty")

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
  call itb_pipeline_free(pipe)

  ! Register an 8-entry width-256 innerHashes constellation, layers
  ! off; the registered profile round-trips; a duplicate name is a
  ! distinct status.
  call itb_opts_set(mixed, "mode", "singlemsg-nomac")
  call itb_opts_set(mixed, "width", "256")
  call itb_opts_set(mixed, "innerHashes", &
      "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256")
  call itb_opts_set(mixed, "keyBits", "1024")
  call itb_opts_set(mixed, "parallaxOn", "false")
  call itb_opts_set(mixed, "wrapperOn", "false")
  call itb_register_profile("fortran-binding-test-mixed", mixed, err)
  call expect_ok(err, "register profile")

  call itb_pipeline_init(sender, "fortran-binding-test-mixed", empty, err)
  call expect_ok(err, "init registered profile")
  call itb_pipeline_open(receiver, "fortran-binding-test-mixed", &
      sender%blob, empty, err)
  call expect_ok(err, "open registered profile")
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

  call itb_register_profile("fortran-binding-test-mixed", mixed, err)
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
  call check(itb_hash_count() > 0, "hash count positive")
  call itb_hash_name(0, name, err)
  call expect_ok(err, "hash name 0")
  call check(len(name) > 0, "hash name non-empty")
  call check(itb_hash_width(0) > 0, "hash width positive")

  call test_done("test_errors")
end program
