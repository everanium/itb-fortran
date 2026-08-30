! Init -> Rekey -> Open receiver with the rotated blob -> round trip.

program test_rekey
  use itb
  use itb_test_helpers
  implicit none

  character(*), parameter :: PROFILE = "singlemsg-triple-mac-v1"

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver
  type(itb_error_t)    :: err
  integer(c_int8_t), allocatable :: blob_before(:), plain(:), wire(:), back(:)
  integer(c_int8_t) :: perm(32), wrap(32)
  logical :: blob_changed
  integer :: i

  call itb_pipeline_init(sender, PROFILE, opts, err)
  call expect_ok(err, "init")
  blob_before = sender%blob

  perm = byte_of(17)
  wrap = byte_of(34)
  call itb_pipeline_rekey(sender, perm, wrap, err)
  call expect_ok(err, "rekey")

  blob_changed = (size(sender%blob) /= size(blob_before))
  if (.not. blob_changed) blob_changed = .not. all(sender%blob == blob_before)
  call check(blob_changed, "rekey refreshes the blob")

  call itb_pipeline_open(receiver, PROFILE, sender%blob, opts, err)
  call expect_ok(err, "open with rotated blob")

  allocate (plain(18))
  do i = 1, size(plain)
    plain(i) = byte_of(32 + i)
  end do
  call itb_encrypt_message(sender, plain, wire, err)
  call expect_ok(err, "encrypt post-rekey")
  call itb_decrypt_message(receiver, wire, back, err)
  call expect_ok(err, "decrypt post-rekey")
  call check_bytes_equal(back, plain, "post-rekey round trip")

  call itb_pipeline_free(receiver)
  call itb_pipeline_free(sender)
  call test_done("test_rekey")
end program
