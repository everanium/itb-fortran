! test_wrapper.f90 -- format-deniability wrapper coverage tests.
!
! Exercises every entry point in the `itb_wrapper` module across the
! three outer ciphers (AES-128-CTR / ChaCha20 / SipHash-2-4 in CTR
! mode):
!
!   * `itb_wrapper_key_size` / `itb_wrapper_nonce_size` size accessors
!     -- canonical 16/16, 32/12, 16/16 byte counts.
!   * `itb_wrapper_generate_key` -- correct length, non-zero entropy
!     (two consecutive draws produce different keys with overwhelming
!     probability).
!   * `itb_wrap` / `itb_unwrap` -- round-trips a CSPRNG-token
!     plaintext at three sizes (small / medium / large).
!   * `itb_wrap_in_place` / `itb_unwrap_in_place` -- mutates blob /
!     wire in place, verifies the recovered slice matches the original
!     plaintext.
!   * `itb_wrap_stream_writer_t` / `itb_unwrap_stream_reader_t`
!     -- streaming round-trip with a chunked feed pattern, mirroring
!     the User-Driven Loop shape the eitb runner exercises.
!   * Cross-stream determinism -- two independent
!     `(key, fresh-nonce)` sessions on the same plaintext produce
!     distinct wires (CSPRNG nonce ensures fresh keystream).
!   * Wrong-key rejection -- decrypting with a different outer key
!     succeeds at the round-trip layer (the wrapper layer is
!     unauthenticated by design) but produces non-matching bytes;
!     the test asserts the recovered plaintext does NOT equal the
!     original under wrong key.

program test_wrapper
  use itb_kinds
  use itb_wrapper
  use itb_errors
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_wrapper"

  integer, parameter :: CIPHERS(3) = &
    [ITB_WRAPPER_CIPHER_AES_128_CTR,                          &
     ITB_WRAPPER_CIPHER_CHACHA20,                             &
     ITB_WRAPPER_CIPHER_SIPHASH24]
  integer, parameter :: EXPECTED_KEY_LEN(3)   = [16, 32, 16]
  integer, parameter :: EXPECTED_NONCE_LEN(3) = [16, 12, 16]
  integer, parameter :: PLAINTEXT_SIZES(3)    = [1, 1024, 65536]

  call test_size_accessors()
  call test_generate_key()
  call test_derive_key()
  call test_wrap_unwrap_roundtrip()
  call test_wrap_unwrap_in_place_roundtrip()
  call test_stream_roundtrip()
  call test_freshness()
  call test_wrong_key_distinguishes()

  call test_pass(TEST_NAME)

contains

  ! Per-process xorshift64* token-stream identical to the existing
  ! test fixtures' helpers. Yields non-deterministic test bytes
  ! across calls within one program execution.
  function token_bytes(n) result(out)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: out(:)
    integer(c_int64_t), save :: ctr = int(z'C0FFEEBABE12FACE', c_int64_t)
    integer(c_int64_t) :: state
    integer :: i
    integer(c_int64_t), parameter :: GOLD = int(z'4E3779B97F4A7C15', c_int64_t)
    integer(c_int64_t), parameter :: MULT = 6364136223846793005_c_int64_t
    integer(c_int64_t), parameter :: ADDC = 1442695040888963407_c_int64_t

    ctr   = ctr + GOLD
    state = ctr
    if (n <= 0) then
      allocate (out(0))
      return
    end if
    allocate (out(n))
    do i = 1, n
      state  = state * MULT + ADDC
      out(i) = int(iand(ishft(state, -33), 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine test_size_accessors()
    integer :: i, klen, nlen
    integer(itb_status_kind) :: rc
    do i = 1, size(CIPHERS)
      call itb_wrapper_key_size(CIPHERS(i), klen, rc)
      call assert_status_ok(TEST_NAME, "key_size status", rc)
      call assert_int_eq(TEST_NAME, "key length", klen, EXPECTED_KEY_LEN(i))
      call itb_wrapper_nonce_size(CIPHERS(i), nlen, rc)
      call assert_status_ok(TEST_NAME, "nonce_size status", rc)
      call assert_int_eq(TEST_NAME, "nonce length", nlen, EXPECTED_NONCE_LEN(i))
    end do
    ! Out-of-range cipher is rejected.
    call itb_wrapper_key_size(99, klen, rc)
    call assert_status_eq(TEST_NAME, "bad cipher key_size", rc, STATUS_BAD_INPUT)
  end subroutine

  subroutine test_generate_key()
    integer :: i
    integer(itb_byte_kind), allocatable :: key1(:), key2(:)
    integer(itb_status_kind) :: rc
    logical :: differ
    integer :: j
    do i = 1, size(CIPHERS)
      call itb_wrapper_generate_key(CIPHERS(i), key1, rc)
      call assert_status_ok(TEST_NAME, "generate_key first", rc)
      call assert_int_eq(TEST_NAME, "key1 length", size(key1), EXPECTED_KEY_LEN(i))
      call itb_wrapper_generate_key(CIPHERS(i), key2, rc)
      call assert_status_ok(TEST_NAME, "generate_key second", rc)
      call assert_int_eq(TEST_NAME, "key2 length", size(key2), EXPECTED_KEY_LEN(i))
      ! Two consecutive CSPRNG draws should differ at >= one byte.
      differ = .false.
      do j = 1, size(key1)
        if (key1(j) /= key2(j)) then
          differ = .true.
          exit
        end if
      end do
      call assert_true(TEST_NAME, "consecutive keys differ", differ)
      deallocate (key1, key2)
    end do
  end subroutine

  ! Deterministic key derivation from a 32-byte master (a stand-in for
  ! an ML-KEM shared secret; the binding ships no KEM). Per cipher the
  ! derived key is length-correct, two derivations from the same
  ! (cipher, master) agree, and the key drives a full wrap / unwrap
  ! round-trip.
  subroutine test_derive_key()
    integer :: i, j, nlen
    integer(itb_byte_kind), allocatable :: master(:)
    integer(itb_byte_kind), allocatable :: key1(:), key2(:)
    integer(itb_byte_kind), allocatable :: plaintext(:), wire(:), recovered(:)
    integer(itb_status_kind) :: rc
    logical :: same
    master = token_bytes(32)
    do i = 1, size(CIPHERS)
      call itb_wrapper_derive_key(CIPHERS(i), master, key1, rc)
      call assert_status_ok(TEST_NAME, "derive_key first", rc)
      call assert_int_eq(TEST_NAME, "derived key length",                    &
                          size(key1), EXPECTED_KEY_LEN(i))
      ! Determinism: same (cipher, master) yields the same key.
      call itb_wrapper_derive_key(CIPHERS(i), master, key2, rc)
      call assert_status_ok(TEST_NAME, "derive_key second", rc)
      same = size(key1) == size(key2)
      if (same) then
        do j = 1, size(key1)
          if (key1(j) /= key2(j)) then
            same = .false.
            exit
          end if
        end do
      end if
      call assert_true(TEST_NAME, "derive_key deterministic", same)
      ! The derived key round-trips through wrap / unwrap.
      call itb_wrapper_nonce_size(CIPHERS(i), nlen, rc)
      call assert_status_ok(TEST_NAME, "nonce_size derive", rc)
      plaintext = token_bytes(1024)
      call itb_wrap(CIPHERS(i), key1, plaintext, wire, rc)
      call assert_status_ok(TEST_NAME, "wrap with derived key", rc)
      call itb_unwrap(CIPHERS(i), key1, wire, recovered, rc)
      call assert_status_ok(TEST_NAME, "unwrap with derived key", rc)
      call assert_bytes_eq(TEST_NAME, "derived key roundtrip bytes",         &
                            recovered, plaintext)
      deallocate (key1, key2, plaintext, wire, recovered)
    end do
    deallocate (master)
  end subroutine

  subroutine test_wrap_unwrap_roundtrip()
    integer :: i, sz_idx, nlen
    integer(itb_byte_kind), allocatable :: key(:), plaintext(:), wire(:), recovered(:)
    integer(itb_status_kind) :: rc
    do i = 1, size(CIPHERS)
      call itb_wrapper_generate_key(CIPHERS(i), key, rc)
      call assert_status_ok(TEST_NAME, "gen_key roundtrip", rc)
      call itb_wrapper_nonce_size(CIPHERS(i), nlen, rc)
      call assert_status_ok(TEST_NAME, "nonce_size roundtrip", rc)
      do sz_idx = 1, size(PLAINTEXT_SIZES)
        plaintext = token_bytes(PLAINTEXT_SIZES(sz_idx))
        call itb_wrap(CIPHERS(i), key, plaintext, wire, rc)
        call assert_status_ok(TEST_NAME, "wrap roundtrip", rc)
        call assert_int_eq(TEST_NAME, "wire length",                          &
                            size(wire), nlen + size(plaintext))
        call itb_unwrap(CIPHERS(i), key, wire, recovered, rc)
        call assert_status_ok(TEST_NAME, "unwrap roundtrip", rc)
        call assert_bytes_eq(TEST_NAME, "wrap roundtrip bytes",                &
                              recovered, plaintext)
        deallocate (plaintext, wire, recovered)
      end do
      deallocate (key)
    end do
  end subroutine

  subroutine test_wrap_unwrap_in_place_roundtrip()
    integer :: i, sz_idx, nlen, body_first
    integer(itb_byte_kind), allocatable :: key(:), plaintext(:), nonce(:)
    integer(itb_byte_kind), allocatable :: blob(:), wire(:), expected(:)
    integer(itb_status_kind) :: rc
    integer :: j

    do i = 1, size(CIPHERS)
      call itb_wrapper_generate_key(CIPHERS(i), key, rc)
      call assert_status_ok(TEST_NAME, "gen_key in_place", rc)
      call itb_wrapper_nonce_size(CIPHERS(i), nlen, rc)
      call assert_status_ok(TEST_NAME, "nonce_size in_place", rc)
      do sz_idx = 1, size(PLAINTEXT_SIZES)
        plaintext = token_bytes(PLAINTEXT_SIZES(sz_idx))
        ! Snapshot for byte-equality check.
        allocate (expected(size(plaintext)))
        expected(:) = plaintext(:)
        ! Wrap in place: blob is mutated, nonce is filled.
        allocate (blob(size(plaintext)))
        blob(:) = plaintext(:)
        call itb_wrap_in_place(CIPHERS(i), key, blob, nonce, rc)
        call assert_status_ok(TEST_NAME, "wrap_in_place", rc)
        call assert_int_eq(TEST_NAME, "in_place nonce length",                 &
                            size(nonce), nlen)
        ! Compose `nonce || blob` -- identical to the eitb message-side
        ! pattern.
        allocate (wire(nlen + size(blob)))
        do j = 1, nlen
          wire(j) = nonce(j)
        end do
        do j = 1, size(blob)
          wire(nlen + j) = blob(j)
        end do
        call itb_unwrap_in_place(CIPHERS(i), key, wire, body_first, rc)
        call assert_status_ok(TEST_NAME, "unwrap_in_place", rc)
        call assert_int_eq(TEST_NAME, "body_first index",                       &
                            body_first, nlen + 1)
        call assert_bytes_eq(TEST_NAME, "in_place roundtrip bytes",            &
                              wire(body_first:size(wire)), expected)
        deallocate (plaintext, expected, blob, nonce, wire)
      end do
      deallocate (key)
    end do
  end subroutine

  subroutine test_stream_roundtrip()
    integer :: i
    integer(itb_byte_kind), allocatable :: key(:), plaintext(:), nonce(:)
    integer(itb_byte_kind), allocatable, target :: wire_body(:)
    integer(itb_byte_kind), allocatable, target :: recovered(:)
    integer(itb_byte_kind), allocatable, target :: src_chunk(:), dst_chunk(:)
    integer(itb_byte_kind), allocatable :: nonce_copy(:)
    type(itb_wrap_stream_writer_t)   :: writer
    type(itb_unwrap_stream_reader_t) :: reader
    integer(itb_status_kind) :: rc
    integer :: total, off, n, chunk

    chunk = 4096
    total = 32768

    do i = 1, size(CIPHERS)
      call itb_wrapper_generate_key(CIPHERS(i), key, rc)
      call assert_status_ok(TEST_NAME, "gen_key stream", rc)
      plaintext = token_bytes(total)
      ! Encrypt side -- emit chunked plaintext through the writer.
      call itb_wrap_stream_writer_new(CIPHERS(i), key, writer, nonce, rc)
      call assert_status_ok(TEST_NAME, "stream writer new", rc)
      allocate (wire_body(total))
      off = 0
      do while (off < total)
        n = min(chunk, total - off)
        allocate (src_chunk(n))
        allocate (dst_chunk(n))
        src_chunk(:) = plaintext(off + 1 : off + n)
        call writer%update(src_chunk, dst_chunk, rc)
        call assert_status_ok(TEST_NAME, "writer update", rc)
        wire_body(off + 1 : off + n) = dst_chunk(:)
        deallocate (src_chunk, dst_chunk)
        off = off + n
      end do
      call writer%destroy()
      ! Save nonce before destroying writer (already saved in `nonce`).
      allocate (nonce_copy(size(nonce)))
      nonce_copy(:) = nonce(:)
      ! Decrypt side -- mirror.
      call itb_unwrap_stream_reader_new(CIPHERS(i), key, nonce_copy, reader, rc)
      call assert_status_ok(TEST_NAME, "stream reader new", rc)
      allocate (recovered(total))
      off = 0
      do while (off < total)
        n = min(chunk, total - off)
        allocate (src_chunk(n))
        allocate (dst_chunk(n))
        src_chunk(:) = wire_body(off + 1 : off + n)
        call reader%update(src_chunk, dst_chunk, rc)
        call assert_status_ok(TEST_NAME, "reader update", rc)
        recovered(off + 1 : off + n) = dst_chunk(:)
        deallocate (src_chunk, dst_chunk)
        off = off + n
      end do
      call reader%destroy()
      call assert_bytes_eq(TEST_NAME, "stream roundtrip", recovered, plaintext)
      deallocate (key, plaintext, nonce, nonce_copy, wire_body, recovered)
    end do
  end subroutine

  subroutine test_freshness()
    ! Two `itb_wrap` calls on the same `(key, plaintext)` pair must
    ! produce different wires -- the per-call CSPRNG nonce makes the
    ! keystream fresh per session.
    integer :: i
    integer(itb_byte_kind), allocatable :: key(:), plaintext(:), w1(:), w2(:)
    integer(itb_status_kind) :: rc
    logical :: differ
    integer :: j

    do i = 1, size(CIPHERS)
      call itb_wrapper_generate_key(CIPHERS(i), key, rc)
      call assert_status_ok(TEST_NAME, "gen_key freshness", rc)
      plaintext = token_bytes(256)
      call itb_wrap(CIPHERS(i), key, plaintext, w1, rc)
      call assert_status_ok(TEST_NAME, "wrap1 freshness", rc)
      call itb_wrap(CIPHERS(i), key, plaintext, w2, rc)
      call assert_status_ok(TEST_NAME, "wrap2 freshness", rc)
      differ = .false.
      do j = 1, size(w1)
        if (w1(j) /= w2(j)) then
          differ = .true.
          exit
        end if
      end do
      call assert_true(TEST_NAME, "fresh nonces differ", differ)
      deallocate (key, plaintext, w1, w2)
    end do
  end subroutine

  subroutine test_wrong_key_distinguishes()
    ! Decrypting with a different outer key still succeeds at the FFI
    ! layer (the wrap layer is unauthenticated) but the recovered
    ! bytes will not equal the original plaintext.
    integer :: i, j
    integer(itb_byte_kind), allocatable :: k1(:), k2(:), plaintext(:), wire(:), recovered(:)
    integer(itb_status_kind) :: rc
    logical :: any_differ

    do i = 1, size(CIPHERS)
      call itb_wrapper_generate_key(CIPHERS(i), k1, rc)
      call assert_status_ok(TEST_NAME, "gen_key k1", rc)
      call itb_wrapper_generate_key(CIPHERS(i), k2, rc)
      call assert_status_ok(TEST_NAME, "gen_key k2", rc)
      plaintext = token_bytes(512)
      call itb_wrap(CIPHERS(i), k1, plaintext, wire, rc)
      call assert_status_ok(TEST_NAME, "wrap wrong key", rc)
      call itb_unwrap(CIPHERS(i), k2, wire, recovered, rc)
      call assert_status_ok(TEST_NAME, "unwrap wrong key", rc)
      call assert_int_eq(TEST_NAME, "recovered length",                         &
                          size(recovered), size(plaintext))
      any_differ = .false.
      do j = 1, size(plaintext)
        if (recovered(j) /= plaintext(j)) then
          any_differ = .true.
          exit
        end if
      end do
      call assert_true(TEST_NAME, "wrong key produces different bytes", any_differ)
      deallocate (k1, k2, plaintext, wire, recovered)
    end do
  end subroutine

end program test_wrapper
