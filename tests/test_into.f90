! Coverage for the reusable-buffer *_into cipher entries: wire
! compatibility with the legacy exact-size paths (both directions,
! all three surfaces), cross-call buffer reuse with dirty tails, and
! caller-pre-allocated oversized scratch.

program test_into
  use, intrinsic :: iso_c_binding, only: c_size_t
  use, intrinsic :: iso_fortran_env, only: int64
  use itb
  use itb_test_helpers
  implicit none

  character(*), parameter :: MSG_PROFILE = "singlemsg-triple-mac-v1"
  character(*), parameter :: STREAM_PROFILE = "streaming-aead-triple-mac-v1"

  type(itb_opts_t)     :: opts
  type(itb_pipeline_t) :: sender, receiver
  type(itb_error_t)    :: err

  ! ---- Case class 1: round trips / wire compatibility ---------------

  call itb_pipeline_init(sender, MSG_PROFILE, opts, err)
  call expect_ok(err, "init message")
  call load_from(sender, receiver, err)
  call expect_ok(err, "open message")

  call round_trip_message(65536)
  call reuse_sequence_message()
  call oversized_message(262144)

  call itb_pipeline_free(receiver)
  call itb_pipeline_free(sender)

  call itb_pipeline_init(sender, STREAM_PROFILE, opts, err)
  call expect_ok(err, "init stream")
  call load_from(sender, receiver, err)
  call expect_ok(err, "open stream")

  call round_trip_one_shot(65536)
  call round_trip_pump(2**20)
  call reuse_sequence_pump()
  call oversized_pump(262144)

  call itb_pipeline_free(receiver)
  call itb_pipeline_free(sender)

  call test_done("test_into")

contains

  ! encrypt_message_into wire decrypts through the legacy path, and
  ! legacy wire decrypts through decrypt_message_into.
  subroutine round_trip_message(n)
    integer, intent(in) :: n
    integer(c_int8_t), allocatable         :: plain(:), legacy_wire(:), back(:)
    integer(c_int8_t), allocatable, target :: wire_s(:), back_s(:)
    integer(c_size_t) :: n_wire, n_back

    allocate (plain(n))
    call fill_xorshift(plain, int(n, int64))

    call itb_encrypt_message_into(sender, plain, wire_s, n_wire, err)
    call expect_ok(err, "message: encrypt _into")
    call check(n_wire > 0_c_size_t, "message: n_wire positive")
    call itb_decrypt_message(receiver, wire_s(1:n_wire), back, err)
    call expect_ok(err, "message: legacy decrypt of _into wire")
    call check_bytes_equal(back, plain, "message: _into wire round trip")

    call itb_encrypt_message(sender, plain, legacy_wire, err)
    call expect_ok(err, "message: legacy encrypt")
    call itb_decrypt_message_into(receiver, legacy_wire, back_s, n_back, err)
    call expect_ok(err, "message: decrypt _into of legacy wire")
    call check_bytes_equal(back_s(1:n_back), plain, &
        "message: legacy wire _into round trip")
  end subroutine

  ! Same cross-compatibility pattern on the one-shot stream surface.
  subroutine round_trip_one_shot(n)
    integer, intent(in) :: n
    integer(c_int8_t), allocatable         :: plain(:), legacy_wire(:), back(:)
    integer(c_int8_t), allocatable, target :: wire_s(:), back_s(:)
    integer(c_size_t) :: n_wire, n_back

    allocate (plain(n))
    call fill_xorshift(plain, int(n, int64) + 1_int64)

    call itb_encrypt_stream_one_shot_into(sender, plain, wire_s, n_wire, err)
    call expect_ok(err, "one-shot: encrypt _into")
    call check(n_wire > 0_c_size_t, "one-shot: n_wire positive")
    call itb_decrypt_stream_one_shot(receiver, wire_s(1:n_wire), back, err)
    call expect_ok(err, "one-shot: legacy decrypt of _into wire")
    call check_bytes_equal(back, plain, "one-shot: _into wire round trip")

    call itb_encrypt_stream_one_shot(sender, plain, legacy_wire, err)
    call expect_ok(err, "one-shot: legacy encrypt")
    call itb_decrypt_stream_one_shot_into(receiver, legacy_wire, back_s, &
        n_back, err)
    call expect_ok(err, "one-shot: decrypt _into of legacy wire")
    call check_bytes_equal(back_s(1:n_back), plain, &
        "one-shot: legacy wire _into round trip")
  end subroutine

  ! Same cross-compatibility pattern on the whole-buffer pump surface.
  subroutine round_trip_pump(n)
    integer, intent(in) :: n
    integer(c_int8_t), allocatable         :: plain(:), legacy_wire(:), back(:)
    integer(c_int8_t), allocatable, target :: wire_s(:), back_s(:)
    integer(c_size_t) :: n_wire, n_back

    allocate (plain(n))
    call fill_xorshift(plain, int(n, int64) + 2_int64)

    call itb_encrypt_stream_pump_into(sender, plain, wire_s, n_wire, err)
    call expect_ok(err, "pump: encrypt _into")
    call check(n_wire > 0_c_size_t, "pump: n_wire positive")
    call itb_decrypt_stream_pump(receiver, wire_s(1:n_wire), back, err)
    call expect_ok(err, "pump: legacy decrypt of _into wire")
    call check_bytes_equal(back, plain, "pump: _into wire round trip")

    call itb_encrypt_stream_pump(sender, plain, legacy_wire, err)
    call expect_ok(err, "pump: legacy encrypt")
    call itb_decrypt_stream_pump_into(receiver, legacy_wire, back_s, &
        n_back, err)
    call expect_ok(err, "pump: decrypt _into of legacy wire")
    call check_bytes_equal(back_s(1:n_back), plain, &
        "pump: legacy wire _into round trip")
  end subroutine

  ! ---- Case class 2: cross-call buffer reuse ------------------------

  ! One encrypt scratch + one decrypt scratch driven through a
  ! small / large / small payload sequence on the message surface;
  ! after the large call the small calls run against a dirty tail,
  ! so content equality in dst(1:n_out) proves no cross-call
  ! contamination in the visible range.
  subroutine reuse_sequence_message()
    integer, parameter :: seq(3) = [4096, 2**20, 8192]
    integer(c_int8_t), allocatable, target :: wire_s(:), back_s(:)
    integer(c_int8_t), allocatable :: plain(:)
    integer(c_size_t) :: n_wire, n_back
    integer :: i

    do i = 1, size(seq)
      allocate (plain(seq(i)))
      call fill_xorshift(plain, int(1000 + i, int64))
      call itb_encrypt_message_into(sender, plain, wire_s, n_wire, err)
      call expect_ok(err, "reuse message: encrypt")
      call itb_decrypt_message_into(receiver, wire_s(1:n_wire), back_s, &
          n_back, err)
      call expect_ok(err, "reuse message: decrypt")
      call check_bytes_equal(back_s(1:n_back), plain, &
          "reuse message: round trip in dirty buffer")
      deallocate (plain)
    end do
  end subroutine

  ! Same reuse sequence on the pump surface (exercises the pump's
  ! up-front sizing keep / grow arms across calls).
  subroutine reuse_sequence_pump()
    integer, parameter :: seq(3) = [4096, 2**20, 8192]
    integer(c_int8_t), allocatable, target :: wire_s(:), back_s(:)
    integer(c_int8_t), allocatable :: plain(:)
    integer(c_size_t) :: n_wire, n_back
    integer :: i

    do i = 1, size(seq)
      allocate (plain(seq(i)))
      call fill_xorshift(plain, int(2000 + i, int64))
      call itb_encrypt_stream_pump_into(sender, plain, wire_s, n_wire, err)
      call expect_ok(err, "reuse pump: encrypt")
      call itb_decrypt_stream_pump_into(receiver, wire_s(1:n_wire), back_s, &
          n_back, err)
      call expect_ok(err, "reuse pump: decrypt")
      call check_bytes_equal(back_s(1:n_back), plain, &
          "reuse pump: round trip in dirty buffer")
      deallocate (plain)
    end do
  end subroutine

  ! ---- Case class 3: caller-pre-allocated oversized scratch ---------

  ! dst sized 4x the payload (above the wire-expansion bound) must be
  ! kept as-is: same size before / after, correct n_out, correct
  ! content, no write past the reported length needed for the round
  ! trip.
  subroutine oversized_message(n)
    integer, intent(in) :: n
    integer(c_int8_t), allocatable, target :: wire_s(:), back_s(:)
    integer(c_int8_t), allocatable :: plain(:)
    integer(c_size_t) :: n_wire, n_back
    integer :: cap_before

    allocate (plain(n))
    call fill_xorshift(plain, int(3000 + n, int64))
    allocate (wire_s(4 * n), back_s(4 * n))
    cap_before = size(wire_s)

    call itb_encrypt_message_into(sender, plain, wire_s, n_wire, err)
    call expect_ok(err, "oversized message: encrypt")
    call check(size(wire_s) == cap_before, &
        "oversized message: encrypt scratch kept")
    call check(n_wire > int(n, c_size_t), "oversized message: n_wire sane")
    call check(n_wire <= int(size(wire_s), c_size_t), &
        "oversized message: n_wire within cap")

    call itb_decrypt_message_into(receiver, wire_s(1:n_wire), back_s, &
        n_back, err)
    call expect_ok(err, "oversized message: decrypt")
    call check(size(back_s) == 4 * n, "oversized message: decrypt scratch kept")
    call check_bytes_equal(back_s(1:n_back), plain, &
        "oversized message: round trip")
  end subroutine

  ! Same oversized-scratch checks on the pump surface (the drain
  ! loop must stay inside the caller's buffer without regrowing it).
  subroutine oversized_pump(n)
    integer, intent(in) :: n
    integer(c_int8_t), allocatable, target :: wire_s(:), back_s(:)
    integer(c_int8_t), allocatable :: plain(:)
    integer(c_size_t) :: n_wire, n_back
    integer :: cap_before

    allocate (plain(n))
    call fill_xorshift(plain, int(4000 + n, int64))
    allocate (wire_s(4 * n), back_s(4 * n))
    cap_before = size(wire_s)

    call itb_encrypt_stream_pump_into(sender, plain, wire_s, n_wire, err)
    call expect_ok(err, "oversized pump: encrypt")
    call check(size(wire_s) == cap_before, "oversized pump: encrypt scratch kept")
    call check(n_wire > int(n, c_size_t), "oversized pump: n_wire sane")
    call check(n_wire <= int(size(wire_s), c_size_t), &
        "oversized pump: n_wire within cap")

    call itb_decrypt_stream_pump_into(receiver, wire_s(1:n_wire), back_s, &
        n_back, err)
    call expect_ok(err, "oversized pump: decrypt")
    call check(size(back_s) == 4 * n, "oversized pump: decrypt scratch kept")
    call check_bytes_equal(back_s(1:n_back), plain, "oversized pump: round trip")
  end subroutine

end program
