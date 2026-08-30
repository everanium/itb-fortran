! Init -> blob -> Open -> EncryptMessage -> DecryptMessage round trip.

program test_smoke
  use itb
  use itb_test_helpers
  implicit none

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: plain(:), wire(:), back(:)
  integer :: i

  call itb_pipeline_init(sender, "singlemsg-triple-mac-v1", opts, err)
  call expect_ok(err, "init")
  call check(size(sender%blob) > 0, "blob non-empty")

  call itb_pipeline_open(receiver, "singlemsg-triple-mac-v1", &
      sender%blob, opts, err)
  call expect_ok(err, "open")

  allocate (plain(24))
  do i = 1, size(plain)
    plain(i) = byte_of(64 + i)
  end do

  call itb_encrypt_message(sender, plain, wire, err)
  call expect_ok(err, "encrypt_message")
  call check(size(wire) > 0, "wire non-empty")
  call check(.not. (size(wire) == size(plain) .and. all(wire == plain)), &
      "wire differs from plaintext")

  call itb_decrypt_message(receiver, wire, back, err)
  call expect_ok(err, "decrypt_message")
  call check_bytes_equal(back, plain, "round trip")

  call itb_pipeline_free(receiver)
  call itb_pipeline_free(sender)
  call test_done("test_smoke")
end program
