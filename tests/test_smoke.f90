! Init -> Save -> Load -> EncryptMessage -> DecryptMessage round trip.

program test_smoke
  use itb3
  use itb_test_helpers
  implicit none

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver, k1, k2, bad
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: plain(:), wire(:), back(:), blob(:)
  integer(c_int8_t), allocatable :: b1(:), b2(:), kwire(:), kback(:)
  integer(c_int8_t) :: flat(8 * 32), dup_flat(8 * 32), short_flat(8 + 7 * 32)
  integer(c_size_t) :: lens(8), short_lens(8)
  integer :: i, j

  call itb_pipeline_init(sender, "singlemsg-triple-mac-v1", opts, err)
  call expect_ok(err, "init")
  call itb_pipeline_save(sender, blob, err)
  call expect_ok(err, "save")
  call check(size(blob) > 0, "blob non-empty")

  call load_from(sender, receiver, err)
  call expect_ok(err, "load")

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

  ! itb_pipeline_init_keys determinism and error propagation.
  lens = 32_c_size_t
  do i = 0, 7
    do j = 1, 32
      flat(i * 32 + j) = byte_of(17 * (i + 1))
    end do
  end do

  call itb_pipeline_init_keys(k1, "singlemsg-triple-mac-v1", opts, flat, &
      lens, err)
  call expect_ok(err, "init_keys k1")
  call itb_pipeline_init_keys(k2, "singlemsg-triple-mac-v1", opts, flat, &
      lens, err)
  call expect_ok(err, "init_keys k2")

  call itb_pipeline_save(k1, b1, err)
  call expect_ok(err, "save k1")
  call itb_pipeline_save(k2, b2, err)
  call expect_ok(err, "save k2")
  call check_bytes_equal(b1, b2, "init_keys deterministic blob")

  call itb_encrypt_message(k1, plain, kwire, err)
  call expect_ok(err, "init_keys encrypt")
  call itb_decrypt_message(k2, kwire, kback, err)
  call expect_ok(err, "init_keys decrypt")
  call check_bytes_equal(kback, plain, "init_keys round trip")

  call itb_pipeline_free(k1)
  call itb_pipeline_free(k2)

  ! Duplicate key must fail with ITB_STATUS_BAD_INPUT.
  dup_flat = flat
  dup_flat(33:64) = dup_flat(1:32)
  call itb_pipeline_init_keys(bad, "singlemsg-triple-mac-v1", opts, &
      dup_flat, lens, err)
  call check(err%status == ITB_STATUS_BAD_INPUT, "duplicate key BadInput")

  ! Short (< 16 bytes) key must fail with ITB_STATUS_BAD_INPUT.
  short_flat = flat(1:(8 + 7 * 32))
  short_lens = 32_c_size_t
  short_lens(1) = 8_c_size_t
  call itb_pipeline_init_keys(bad, "singlemsg-triple-mac-v1", opts, &
      short_flat, short_lens, err)
  call check(err%status == ITB_STATUS_BAD_INPUT, "short key BadInput")

  call test_done("test_smoke")
end program
