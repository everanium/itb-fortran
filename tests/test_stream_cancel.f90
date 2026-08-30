! Freeing an encrypt session mid-flight (no end) cleans up and leaves
! the Pipeline usable.

program test_stream_cancel
  use itb
  use itb_test_helpers
  implicit none

  character(*), parameter :: PROFILE = "streaming-aead-triple-mac-v1"

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver
  type(itb_error_t)    :: err
  type(itb_stream_t)   :: sess
  integer(c_int8_t), allocatable :: chunk(:), plain(:), wire(:), back(:)
  integer :: i

  call itb_pipeline_init(sender, PROFILE, opts, err)
  call expect_ok(err, "init")

  call itb_encrypt_stream_begin(sender, sess, err)
  call expect_ok(err, "stream begin")
  allocate (chunk(100000))
  chunk = byte_of(165)
  call itb_stream_write(sess, chunk, err)
  call expect_ok(err, "stream write")
  ! Freed here without end -- StreamFree cancels the session; the
  ! test passing (process not hanging) is the assertion.
  call itb_stream_free(sess)

  ! The Pipeline stays usable after the cancelled session.
  call itb_pipeline_open(receiver, PROFILE, sender%blob, opts, err)
  call expect_ok(err, "open")
  allocate (plain(13))
  do i = 1, size(plain)
    plain(i) = byte_of(96 + i)
  end do
  call itb_encrypt_message(sender, plain, wire, err)
  call expect_ok(err, "encrypt after cancel")
  call itb_decrypt_message(receiver, wire, back, err)
  call expect_ok(err, "decrypt after cancel")
  call check_bytes_equal(back, plain, "round trip after cancel")

  call itb_pipeline_free(receiver)
  call itb_pipeline_free(sender)
  call test_done("test_stream_cancel")
end program
