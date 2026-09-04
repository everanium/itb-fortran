! Round trip through the stream pumps on a Streaming AEAD profile,
! plus one-shot / pump cross-compatibility.

program test_stream_pump
  use itb
  use itb_test_helpers
  implicit none

  character(*), parameter :: PROFILE = "streaming-aead-triple-mac-v1"

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: plain(:), wire(:), back(:), back2(:)

  call itb_pipeline_init(sender, PROFILE, opts, err)
  call expect_ok(err, "init")
  call load_from(sender, receiver, err)
  call expect_ok(err, "open")

  ! Pump round trip at 1 MiB.
  allocate (plain(2**20))
  call fill_mod(plain, 251)
  call itb_encrypt_stream_pump(sender, plain, wire, err)
  call expect_ok(err, "encrypt pump")
  call check(size(wire) > 0, "wire non-empty")
  call itb_decrypt_stream_pump(receiver, wire, back, err)
  call expect_ok(err, "decrypt pump")
  call check_bytes_equal(back, plain, "pump round trip")
  deallocate (plain, wire, back)

  ! One-shot encrypt decrypts through both the pump and the one-shot
  ! path.
  allocate (plain(65536))
  call fill_mod(plain, 199)
  call itb_encrypt_stream_one_shot(sender, plain, wire, err)
  call expect_ok(err, "encrypt one-shot")
  call itb_decrypt_stream_pump(receiver, wire, back, err)
  call expect_ok(err, "decrypt pump of one-shot wire")
  call check_bytes_equal(back, plain, "pump matches one-shot")
  call itb_decrypt_stream_one_shot(receiver, wire, back2, err)
  call expect_ok(err, "decrypt one-shot")
  call check_bytes_equal(back2, plain, "one-shot matches one-shot")

  call itb_pipeline_free(receiver)
  call itb_pipeline_free(sender)
  call test_done("test_stream_pump")
end program
