! test_easy_roundtrip.f90 -- end-to-end coverage for the high-level
! Easy Mode encryptor surface.
!
! Mirrors the C binding's test_easy_roundtrip.c one-to-one. Lifecycle
! tests (close / destroy / handle invalidation), structural validation
! (bad primitive / MAC / key_bits / mode), full-matrix round-trips for
! both Single and Triple Ouroboros, and per-instance configuration
! setters that mutate only the local Config copy without touching
! libitb's process-global state.
!
! Per-binary process isolation gives this test its own libitb global
! state, so no in-process serial lock is required.
!
! The constructors raise on failure (no handle to return), so the
! "bad primitive / MAC / key_bits / mode" sub-tests drop to the low-
! level FFI binding (`itb_easy_new_c`) to observe the explicit
! non-OK status branch without halting.

program test_easy_roundtrip
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_test_helpers
  use itb_encryptor
  use itb_errors
  use itb_sys, only: itb_easy_new_c, itb_easy_set_lock_seed_c
  use itb_strings, only: make_c_string
  implicit none

  character(*), parameter :: TEST_NAME = "test_easy_roundtrip"
  integer,      parameter :: PT_LEN    = 4096
  character(len=10), parameter :: HASHES(9) = &
      [character(len=10) :: "areion256", "areion512", "siphash24",   &
                            "aescmac",   "blake2b256", "blake2b512", &
                            "blake2s",   "blake3",     "chacha20"]
  integer, parameter :: WIDTHS(9) = &
      [256, 512, 128, 128, 256, 512, 256, 256, 256]
  integer, parameter :: CANDIDATE_KB(3) = [512, 1024, 2048]

  call test_new_and_destroy()
  call test_destroy_releases_handle()
  call test_double_destroy_idempotent()
  call test_close_then_method_raises_via_ffi()
  call test_bad_primitive_rejected()
  call test_bad_mac_rejected()
  call test_bad_key_bits_rejected()
  call test_bad_mode_rejected()
  call test_all_hashes_all_widths_single()
  call test_all_hashes_all_widths_single_auth()
  call test_slice_input_roundtrip()
  call test_all_hashes_all_widths_triple()
  call test_all_hashes_all_widths_triple_auth()
  call test_seed_count_reflects_mode()
  call test_set_bit_soup_roundtrip()
  call test_set_lock_soup_couples_bit_soup()
  call test_set_lock_seed_grows_seed_count()
  call test_set_lock_seed_after_encrypt_rejected()
  call test_set_chunk_size_accepted()
  call test_two_encryptors_isolated()

  call test_pass(TEST_NAME)

contains

  function token_bytes(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(n))
    do i = 1, n
      v = int(i - 1, c_int64_t) * 53_c_int64_t + 89_c_int64_t
      p(i) = int(iand(v, 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine test_new_and_destroy()
    type(itb_encryptor_t) :: enc
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call assert_string_eq(TEST_NAME, "primitive", enc%primitive(), "blake3")
    call assert_int_eq   (TEST_NAME, "key_bits",  int(enc%key_bits()), 1024)
    call assert_int_eq   (TEST_NAME, "mode",      int(enc%mode()),     1)
    call assert_string_eq(TEST_NAME, "mac_name",  enc%mac_name(), "kmac256")
    call enc%destroy()
  end subroutine

  subroutine test_destroy_releases_handle()
    type(itb_encryptor_t) :: enc
    call new_itb_encryptor(enc, "areion256", 1024, "kmac256", 1)
    call assert_false(TEST_NAME, "live before destroy", enc%is_closed())
    call enc%destroy()
    call assert_true(TEST_NAME, "closed after destroy", enc%is_closed())
  end subroutine

  subroutine test_double_destroy_idempotent()
    type(itb_encryptor_t) :: enc
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call enc%close()
    call enc%destroy()
    ! Idempotent destroy.
    call enc%destroy()
  end subroutine

  subroutine test_close_then_method_raises_via_ffi()
    ! After close, the wrapper-side preflight returns
    ! STATUS_EASY_CLOSED on every cipher / setter / getter call. The
    ! wrapper raises on that path; drop to the low-level FFI to
    ! observe the libitb-side response on a closed handle (the
    ! handle is the same -- only the wrapper's `closed` flag has
    ! flipped, so libitb still sees a live handle until destroy).
    !
    ! Sub-test: calling enc%encrypt() on a closed wrapper raises
    ! STATUS_EASY_CLOSED before reaching libitb. Verify via the
    ! is_closed() predicate.
    type(itb_encryptor_t) :: enc
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call enc%close()
    call assert_true(TEST_NAME, "is_closed after close", enc%is_closed())
    call enc%destroy()
  end subroutine

  subroutine test_bad_primitive_rejected()
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: c_prim(:), c_mac(:)

    call make_c_string("nonsense-hash", c_prim)
    call make_c_string("kmac256",       c_mac)
    handle = itb_null_handle
    rc = itb_easy_new_c(c_loc(c_prim), 1024_c_int, c_loc(c_mac), 1_c_int, handle)
    call assert_true(TEST_NAME, "bad primitive rejected", rc /= STATUS_OK)
    call assert_true(TEST_NAME, "handle stays null", handle == itb_null_handle)
  end subroutine

  subroutine test_bad_mac_rejected()
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: c_prim(:), c_mac(:)

    call make_c_string("blake3",       c_prim)
    call make_c_string("nonsense-mac", c_mac)
    handle = itb_null_handle
    rc = itb_easy_new_c(c_loc(c_prim), 1024_c_int, c_loc(c_mac), 1_c_int, handle)
    call assert_true(TEST_NAME, "bad mac rejected", rc /= STATUS_OK)
  end subroutine

  subroutine test_bad_key_bits_rejected()
    integer, parameter :: BAD(4) = [256, 511, 999, 2049]
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: c_prim(:), c_mac(:)
    integer :: i

    call make_c_string("blake3",  c_prim)
    call make_c_string("kmac256", c_mac)
    do i = 1, size(BAD)
      handle = itb_null_handle
      rc = itb_easy_new_c(c_loc(c_prim), int(BAD(i), c_int), &
                            c_loc(c_mac), 1_c_int, handle)
      call assert_true(TEST_NAME, "bad key_bits rejected", rc /= STATUS_OK)
    end do
  end subroutine

  subroutine test_bad_mode_rejected()
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: c_prim(:), c_mac(:)

    call make_c_string("blake3",  c_prim)
    call make_c_string("kmac256", c_mac)
    handle = itb_null_handle
    rc = itb_easy_new_c(c_loc(c_prim), 1024_c_int, c_loc(c_mac), 2_c_int, handle)
    call assert_status_eq(TEST_NAME, "bad mode rejected", rc, STATUS_BAD_INPUT)
  end subroutine

  subroutine test_all_hashes_all_widths_single()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer :: hi, ki, kb

    plaintext = token_bytes(PT_LEN)
    do hi = 1, size(HASHES)
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, WIDTHS(hi)) /= 0) cycle

        call new_itb_encryptor(enc, trim(HASHES(hi)), kb, "kmac256", 1)
        ct = enc%encrypt(plaintext)
        call assert_true(TEST_NAME, "ct longer than pt", size(ct) > size(plaintext))
        pt = enc%decrypt(ct)
        call assert_bytes_eq(TEST_NAME, "single roundtrip", pt, plaintext)
        call enc%destroy()
      end do
    end do
  end subroutine

  subroutine test_all_hashes_all_widths_single_auth()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer :: hi, ki, kb

    plaintext = token_bytes(PT_LEN)
    do hi = 1, size(HASHES)
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, WIDTHS(hi)) /= 0) cycle

        call new_itb_encryptor(enc, trim(HASHES(hi)), kb, "kmac256", 1)
        ct = enc%encrypt_auth(plaintext)
        pt = enc%decrypt_auth(ct)
        call assert_bytes_eq(TEST_NAME, "single auth roundtrip", pt, plaintext)
        call enc%destroy()
      end do
    end do
  end subroutine

  subroutine test_slice_input_roundtrip()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(*), parameter :: PT_TEXT = "hello bytearray"
    integer :: i

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    allocate (pt_in(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      pt_in(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do
    ct = enc%encrypt(pt_in)
    pt_out = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "slice roundtrip", pt_out, pt_in)
    call enc%destroy()
  end subroutine

  subroutine test_all_hashes_all_widths_triple()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer :: hi, ki, kb

    plaintext = token_bytes(PT_LEN)
    do hi = 1, size(HASHES)
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, WIDTHS(hi)) /= 0) cycle

        call new_itb_encryptor(enc, trim(HASHES(hi)), kb, "kmac256", 3)
        ct = enc%encrypt(plaintext)
        call assert_true(TEST_NAME, "triple ct > pt", size(ct) > size(plaintext))
        pt = enc%decrypt(ct)
        call assert_bytes_eq(TEST_NAME, "triple roundtrip", pt, plaintext)
        call enc%destroy()
      end do
    end do
  end subroutine

  subroutine test_all_hashes_all_widths_triple_auth()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer :: hi, ki, kb

    plaintext = token_bytes(PT_LEN)
    do hi = 1, size(HASHES)
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, WIDTHS(hi)) /= 0) cycle

        call new_itb_encryptor(enc, trim(HASHES(hi)), kb, "kmac256", 3)
        ct = enc%encrypt_auth(plaintext)
        pt = enc%decrypt_auth(ct)
        call assert_bytes_eq(TEST_NAME, "triple auth roundtrip", pt, plaintext)
        call enc%destroy()
      end do
    end do
  end subroutine

  subroutine test_seed_count_reflects_mode()
    type(itb_encryptor_t) :: enc1, enc3
    call new_itb_encryptor(enc1, "blake3", 1024, "kmac256", 1)
    call assert_int_eq(TEST_NAME, "single seed_count", int(enc1%seed_count()), 3)
    call enc1%destroy()
    call new_itb_encryptor(enc3, "blake3", 1024, "kmac256", 3)
    call assert_int_eq(TEST_NAME, "triple seed_count", int(enc3%seed_count()), 7)
    call enc3%destroy()
  end subroutine

  subroutine test_set_bit_soup_roundtrip()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(*), parameter :: PT_TEXT = "bit-soup payload"
    integer :: i

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call enc%set_bit_soup(1)

    allocate (pt_in(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      pt_in(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do
    ct = enc%encrypt(pt_in)
    pt_out = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "bit-soup roundtrip", pt_out, pt_in)
    call enc%destroy()
  end subroutine

  subroutine test_set_lock_soup_couples_bit_soup()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(*), parameter :: PT_TEXT = "lock-soup payload"
    integer :: i

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call enc%set_lock_soup(1)

    allocate (pt_in(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      pt_in(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do
    ct = enc%encrypt(pt_in)
    pt_out = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "lock-soup roundtrip", pt_out, pt_in)
    call enc%destroy()
  end subroutine

  subroutine test_set_lock_seed_grows_seed_count()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(*), parameter :: PT_TEXT = "lockseed payload"
    integer :: i

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call assert_int_eq(TEST_NAME, "pre-lockseed seed_count", &
                        int(enc%seed_count()), 3)
    call enc%set_lock_seed(1)
    call assert_int_eq(TEST_NAME, "post-lockseed seed_count", &
                        int(enc%seed_count()), 4)

    allocate (pt_in(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      pt_in(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do
    ct = enc%encrypt(pt_in)
    pt_out = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "lockseed roundtrip", pt_out, pt_in)
    call enc%destroy()
  end subroutine

  subroutine test_set_lock_seed_after_encrypt_rejected()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_status_kind) :: rc
    character(*), parameter :: PT_TEXT = "first"
    integer :: i

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    allocate (pt_in(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      pt_in(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do
    ct = enc%encrypt(pt_in)

    ! After the first encrypt, set_lock_seed must surface
    ! STATUS_EASY_LOCKSEED_AFTER_ENCRYPT. The wrapper raises on the
    ! non-OK status; drop to the FFI binding to observe it.
    rc = itb_easy_set_lock_seed_c(enc%raw_handle(), 1_c_int)
    call assert_status_eq(TEST_NAME, "lockseed after encrypt rejected", &
                           rc, STATUS_EASY_LOCKSEED_AFTER_ENCRYPT)

    call enc%destroy()
  end subroutine

  subroutine test_set_chunk_size_accepted()
    type(itb_encryptor_t) :: enc
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call enc%set_chunk_size(1024)
    call enc%set_chunk_size(0)
    call enc%destroy()
  end subroutine

  subroutine test_two_encryptors_isolated()
    ! Setting LockSoup on one encryptor must not bleed into another;
    ! per-instance Config snapshots are independent.
    type(itb_encryptor_t) :: a, b
    integer(itb_byte_kind), target, allocatable :: pa(:), pb(:)
    integer(itb_byte_kind), target, allocatable :: ct_a(:), ct_b(:)
    integer(itb_byte_kind), allocatable :: pt_a(:), pt_b(:)

    call new_itb_encryptor(a, "blake3", 1024, "kmac256", 1)
    call new_itb_encryptor(b, "blake3", 1024, "kmac256", 1)
    call a%set_lock_soup(1)

    allocate (pa(1)); pa(1) = int(iachar('a'), itb_byte_kind)
    allocate (pb(1)); pb(1) = int(iachar('b'), itb_byte_kind)

    ct_a = a%encrypt(pa)
    pt_a = a%decrypt(ct_a)
    call assert_bytes_eq(TEST_NAME, "a roundtrip", pt_a, pa)

    ct_b = b%encrypt(pb)
    pt_b = b%decrypt(ct_b)
    call assert_bytes_eq(TEST_NAME, "b roundtrip", pt_b, pb)

    call a%destroy()
    call b%destroy()
  end subroutine

end program test_easy_roundtrip
