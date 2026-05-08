! test_easy_persistence.f90 -- cross-process persistence round-trip
! tests for the high-level Easy Mode encryptor surface.
!
! Mirrors the C binding's test_easy_persistence.c one-to-one. The
! enc%export_state / enc%import_state / itb_encryptor_peek_config
! triplet is the persistence surface required for any deployment
! where encrypt and decrypt run in different processes (network,
! storage, backup, microservices). Without the JSON-encoded blob
! captured at encrypt-side and re-supplied at decrypt-side, the
! encryptor state cannot be reconstructed and the ciphertext is
! unreadable.
!
! enc%import_state raises on STATUS_EASY_MISMATCH /
! STATUS_EASY_MALFORMED / STATUS_EASY_VERSION_TOO_NEW; the rejection
! sub-tests drop to the low-level FFI binding (`itb_easy_import_c` /
! `itb_easy_peek_config_c`) so the explicit status branch can be
! observed without terminating the test program.

program test_easy_persistence
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_test_helpers
  use itb_encryptor
  use itb_errors
  use itb_sys, only: itb_easy_import_c, itb_easy_peek_config_c
  implicit none

  character(*), parameter :: TEST_NAME = "test_easy_persistence"
  character(len=10), parameter :: HASHES(9) = &
      [character(len=10) :: "areion256", "areion512", "siphash24",   &
                            "aescmac",   "blake2b256", "blake2b512", &
                            "blake2s",   "blake3",     "chacha20"]
  integer, parameter :: WIDTHS(9) = &
      [256, 512, 128, 128, 256, 512, 256, 256, 256]
  integer, parameter :: CANDIDATE_KB(3) = [512, 1024, 2048]
  integer, parameter :: MODES(2) = [1, 3]
  character(len=11), parameter :: MAC_NAMES(3) = &
      [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]

  call test_roundtrip_all_hashes_single()
  call test_roundtrip_all_hashes_triple()
  call test_roundtrip_with_lock_seed()
  call test_roundtrip_with_full_config()
  call test_peek_recovers_metadata()
  call test_peek_malformed_blob()
  call test_peek_too_new_version()
  call test_import_mismatch_primitive()
  call test_import_mismatch_key_bits()
  call test_import_mismatch_mode()
  call test_import_mismatch_mac()
  call test_import_malformed_json()
  call test_import_too_new_version()
  call test_import_wrong_kind()
  call test_mac_key_present()
  call test_prf_key_lengths_per_primitive()
  call test_seed_components_lengths_per_key_bits()
  call test_seed_components_out_of_range()

  call test_pass(TEST_NAME)

contains

  function canonical_plaintext_single() result(p)
    integer(itb_byte_kind), allocatable :: p(:)
    character(*), parameter :: PREFIX = "any binary data, including 0x00 bytes -- "
    integer :: i, prefix_len

    prefix_len = len(PREFIX)
    allocate (p(prefix_len + 256))
    do i = 1, prefix_len
      p(i) = int(iachar(PREFIX(i:i)), itb_byte_kind)
    end do
    do i = 1, 256
      p(prefix_len + i) = int(iand(int(i - 1, c_int64_t), 255_c_int64_t), &
                              itb_byte_kind)
    end do
  end function

  function canonical_plaintext_triple() result(p)
    integer(itb_byte_kind), allocatable :: p(:)
    character(*), parameter :: PREFIX = "triple-mode persistence payload "
    integer :: i, prefix_len

    prefix_len = len(PREFIX)
    allocate (p(prefix_len + 64))
    do i = 1, prefix_len
      p(i) = int(iachar(PREFIX(i:i)), itb_byte_kind)
    end do
    do i = 1, 64
      p(prefix_len + i) = int(iand(int(i - 1, c_int64_t), 255_c_int64_t), &
                              itb_byte_kind)
    end do
  end function

  subroutine roundtrip_one(prim_name, kb, mode_value, plaintext)
    character(*),                                   intent(in) :: prim_name
    integer,                                        intent(in) :: kb, mode_value
    integer(itb_byte_kind), target,                 intent(in) :: plaintext(:)
    type(itb_encryptor_t) :: src, dst
    integer(itb_byte_kind), target, allocatable :: blob(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)

    ! Day 1 -- random encryptor.
    call new_itb_encryptor(src, prim_name, kb, "kmac256", mode_value)
    blob = src%export_state()
    ct   = src%encrypt_auth(plaintext)
    call src%destroy()

    ! Day 2 -- restore from saved blob.
    call new_itb_encryptor(dst, prim_name, kb, "kmac256", mode_value)
    call dst%import_state(blob)
    pt = dst%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "persistence roundtrip", pt, plaintext)
    call dst%destroy()
  end subroutine

  subroutine test_roundtrip_all_hashes_single()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer :: hi, ki, kb

    plaintext = canonical_plaintext_single()
    do hi = 1, size(HASHES)
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, WIDTHS(hi)) /= 0) cycle
        call roundtrip_one(trim(HASHES(hi)), kb, 1, plaintext)
      end do
    end do
  end subroutine

  subroutine test_roundtrip_all_hashes_triple()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer :: hi, ki, kb

    plaintext = canonical_plaintext_triple()
    do hi = 1, size(HASHES)
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, WIDTHS(hi)) /= 0) cycle
        call roundtrip_one(trim(HASHES(hi)), kb, 3, plaintext)
      end do
    end do
  end subroutine

  subroutine test_roundtrip_with_lock_seed()
    ! Activating LockSeed grows the encryptor to 4 (Single) or 8
    ! (Triple) seed slots; the exported blob carries the dedicated
    ! lockSeed material, and import_state on a fresh encryptor
    ! restores the seed slot AND auto-couples the LockSoup + BitSoup
    ! overlays.
    type(itb_encryptor_t) :: src, dst
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: blob(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer, parameter :: CASES_MODE(2)     = [1, 3]
    integer, parameter :: CASES_EXPECTED(2) = [4, 8]
    character(*), parameter :: PREFIX = "lockseed payload "
    integer :: k, i, prefix_len, mode_v, expected

    prefix_len = len(PREFIX)
    allocate (plaintext(prefix_len + 32))
    do i = 1, prefix_len
      plaintext(i) = int(iachar(PREFIX(i:i)), itb_byte_kind)
    end do
    do i = 1, 32
      plaintext(prefix_len + i) = int(iand(int(i - 1, c_int64_t), 255_c_int64_t), &
                                      itb_byte_kind)
    end do

    do k = 1, size(CASES_MODE)
      mode_v   = CASES_MODE(k)
      expected = CASES_EXPECTED(k)

      call new_itb_encryptor(src, "blake3", 1024, "kmac256", mode_v)
      call src%set_lock_seed(1)
      call assert_int_eq(TEST_NAME, "lockseed src seed_count", &
                          int(src%seed_count()), expected)

      blob = src%export_state()
      ct   = src%encrypt_auth(plaintext)
      call src%destroy()

      call new_itb_encryptor(dst, "blake3", 1024, "kmac256", mode_v)
      call assert_int_eq(TEST_NAME, "fresh dst seed_count", &
                          int(dst%seed_count()), expected - 1)
      call dst%import_state(blob)
      call assert_int_eq(TEST_NAME, "post-import seed_count", &
                          int(dst%seed_count()), expected)

      pt = dst%decrypt_auth(ct)
      call assert_bytes_eq(TEST_NAME, "lockseed roundtrip", pt, plaintext)
      call dst%destroy()
    end do
  end subroutine

  subroutine test_roundtrip_with_full_config()
    ! Per-instance configuration knobs (NonceBits, BarrierFill,
    ! BitSoup, LockSoup) round-trip through the state blob along with
    ! the seed material -- no manual mirror set_*() calls required on
    ! the receiver.
    type(itb_encryptor_t) :: src, dst
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: blob(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    character(*), parameter :: PREFIX = "full-config persistence "
    integer :: i, prefix_len

    prefix_len = len(PREFIX)
    allocate (plaintext(prefix_len + 64))
    do i = 1, prefix_len
      plaintext(i) = int(iachar(PREFIX(i:i)), itb_byte_kind)
    end do
    do i = 1, 64
      plaintext(prefix_len + i) = int(iand(int(i - 1, c_int64_t), 255_c_int64_t), &
                                      itb_byte_kind)
    end do

    call new_itb_encryptor(src, "blake3", 1024, "kmac256", 1)
    call src%set_nonce_bits(512)
    call src%set_barrier_fill(4)
    call src%set_bit_soup(1)
    call src%set_lock_soup(1)

    blob = src%export_state()
    ct   = src%encrypt_auth(plaintext)
    call src%destroy()

    ! Receiver -- fresh encryptor without any mirror set_*() calls.
    call new_itb_encryptor(dst, "blake3", 1024, "kmac256", 1)
    call assert_int_eq(TEST_NAME, "pre-import nonce_bits default", &
                        int(dst%nonce_bits()), 128)
    call dst%import_state(blob)
    call assert_int_eq(TEST_NAME, "post-import nonce_bits restored", &
                        int(dst%nonce_bits()), 512)
    call assert_int_eq(TEST_NAME, "post-import header_size", &
                        int(dst%header_size()), 68)

    pt = dst%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "full-config roundtrip", pt, plaintext)
    call dst%destroy()
  end subroutine

  subroutine test_peek_recovers_metadata()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: blob(:)
    character(:), allocatable :: prim_out, mac_out
    integer(itb_int32_kind)   :: kb_out, mode_out
    integer :: hi, ki, kb, mi, mac_i

    do hi = 1, size(HASHES)
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, WIDTHS(hi)) /= 0) cycle
        do mi = 1, size(MODES)
          do mac_i = 1, size(MAC_NAMES)
            call new_itb_encryptor(enc, trim(HASHES(hi)), kb, &
                                    trim(MAC_NAMES(mac_i)), MODES(mi))
            blob = enc%export_state()
            call enc%destroy()

            call itb_encryptor_peek_config(blob, prim_out, kb_out, &
                                             mode_out, mac_out)
            call assert_string_eq(TEST_NAME, "peek primitive", &
                                   prim_out, trim(HASHES(hi)))
            call assert_int_eq   (TEST_NAME, "peek key_bits", int(kb_out),   kb)
            call assert_int_eq   (TEST_NAME, "peek mode",     int(mode_out), MODES(mi))
            call assert_string_eq(TEST_NAME, "peek mac",      &
                                   mac_out, trim(MAC_NAMES(mac_i)))
          end do
        end do
      end do
    end do
  end subroutine

  subroutine peek_status(blob_bytes, status)
    integer(itb_byte_kind), target, intent(in) :: blob_bytes(:)
    integer(itb_status_kind),       intent(out) :: status
    character(kind=c_char), allocatable, target :: prim_buf(:), mac_buf(:)
    integer(itb_size_kind) :: prim_len, mac_len
    integer(itb_int32_kind) :: kb_out, mode_out
    type(c_ptr) :: blob_ptr

    blob_ptr = c_null_ptr
    if (size(blob_bytes) > 0) blob_ptr = c_loc(blob_bytes)

    allocate (prim_buf(64))
    allocate (mac_buf(64))
    prim_len = 0_itb_size_kind
    mac_len  = 0_itb_size_kind
    kb_out   = 0
    mode_out = 0

    status = itb_easy_peek_config_c(blob_ptr,                                 &
                                     int(size(blob_bytes), itb_size_kind),     &
                                     c_loc(prim_buf), 64_itb_size_kind, prim_len,&
                                     kb_out, mode_out,                         &
                                     c_loc(mac_buf), 64_itb_size_kind, mac_len)
  end subroutine

  subroutine test_peek_malformed_blob()
    integer(itb_byte_kind), target, allocatable :: bytes(:)
    integer(itb_status_kind) :: rc
    character(*), parameter :: BAD1 = "not json"
    character(*), parameter :: BAD2 = "{}"
    character(*), parameter :: BAD3 = "{""v"":1}"
    integer :: i

    ! Empty blob.
    allocate (bytes(0))
    call peek_status(bytes, rc)
    call assert_status_eq(TEST_NAME, "peek empty malformed", rc, STATUS_EASY_MALFORMED)
    deallocate (bytes)

    allocate (bytes(len(BAD1)))
    do i = 1, len(BAD1); bytes(i) = int(iachar(BAD1(i:i)), itb_byte_kind); end do
    call peek_status(bytes, rc)
    call assert_status_eq(TEST_NAME, "peek 'not json' malformed", &
                           rc, STATUS_EASY_MALFORMED)
    deallocate (bytes)

    allocate (bytes(len(BAD2)))
    do i = 1, len(BAD2); bytes(i) = int(iachar(BAD2(i:i)), itb_byte_kind); end do
    call peek_status(bytes, rc)
    call assert_status_eq(TEST_NAME, "peek '{}' malformed", rc, STATUS_EASY_MALFORMED)
    deallocate (bytes)

    allocate (bytes(len(BAD3)))
    do i = 1, len(BAD3); bytes(i) = int(iachar(BAD3(i:i)), itb_byte_kind); end do
    call peek_status(bytes, rc)
    call assert_status_eq(TEST_NAME, "peek '{v:1}' malformed", &
                           rc, STATUS_EASY_MALFORMED)
    deallocate (bytes)
  end subroutine

  subroutine test_peek_too_new_version()
    ! PeekConfig conflates "too-new version" with the broader
    ! malformed-shape bucket and surfaces STATUS_EASY_MALFORMED. The
    ! dedicated STATUS_EASY_VERSION_TOO_NEW is reserved for the
    ! Import path.
    integer(itb_byte_kind), target, allocatable :: bytes(:)
    integer(itb_status_kind) :: rc
    character(*), parameter :: BLOB_TXT = "{""v"":99,""kind"":""itb-easy""}"
    integer :: i

    allocate (bytes(len(BLOB_TXT)))
    do i = 1, len(BLOB_TXT)
      bytes(i) = int(iachar(BLOB_TXT(i:i)), itb_byte_kind)
    end do
    call peek_status(bytes, rc)
    call assert_status_eq(TEST_NAME, "peek too-new collapses to malformed", &
                           rc, STATUS_EASY_MALFORMED)
  end subroutine

  subroutine make_baseline_blob(blob)
    integer(itb_byte_kind), allocatable, intent(out) :: blob(:)
    type(itb_encryptor_t) :: src
    call new_itb_encryptor(src, "blake3", 1024, "kmac256", 1)
    blob = src%export_state()
    call src%destroy()
  end subroutine

  subroutine import_status(dst_handle, blob_bytes, status)
    integer(itb_handle_kind),       intent(in)  :: dst_handle
    integer(itb_byte_kind), target, intent(in)  :: blob_bytes(:)
    integer(itb_status_kind),       intent(out) :: status
    type(c_ptr) :: blob_ptr
    blob_ptr = c_null_ptr
    if (size(blob_bytes) > 0) blob_ptr = c_loc(blob_bytes)
    status = itb_easy_import_c(dst_handle, blob_ptr, &
                                 int(size(blob_bytes), itb_size_kind))
  end subroutine

  subroutine test_import_mismatch_primitive()
    integer(itb_byte_kind), target, allocatable :: blob(:)
    type(itb_encryptor_t) :: dst
    integer(itb_status_kind) :: rc
    character(:), allocatable :: field

    call make_baseline_blob(blob)
    call new_itb_encryptor(dst, "blake2s", 1024, "kmac256", 1)
    call import_status(dst%raw_handle(), blob, rc)
    call assert_status_eq(TEST_NAME, "primitive mismatch", rc, STATUS_EASY_MISMATCH)
    field = itb_last_mismatch_field()
    call assert_string_eq(TEST_NAME, "mismatch field primitive", field, "primitive")
    call dst%destroy()
  end subroutine

  subroutine test_import_mismatch_key_bits()
    integer(itb_byte_kind), target, allocatable :: blob(:)
    type(itb_encryptor_t) :: dst
    integer(itb_status_kind) :: rc
    character(:), allocatable :: field

    call make_baseline_blob(blob)
    call new_itb_encryptor(dst, "blake3", 2048, "kmac256", 1)
    call import_status(dst%raw_handle(), blob, rc)
    call assert_status_eq(TEST_NAME, "key_bits mismatch", rc, STATUS_EASY_MISMATCH)
    field = itb_last_mismatch_field()
    call assert_string_eq(TEST_NAME, "mismatch field key_bits", field, "key_bits")
    call dst%destroy()
  end subroutine

  subroutine test_import_mismatch_mode()
    integer(itb_byte_kind), target, allocatable :: blob(:)
    type(itb_encryptor_t) :: dst
    integer(itb_status_kind) :: rc
    character(:), allocatable :: field

    call make_baseline_blob(blob)
    call new_itb_encryptor(dst, "blake3", 1024, "kmac256", 3)
    call import_status(dst%raw_handle(), blob, rc)
    call assert_status_eq(TEST_NAME, "mode mismatch", rc, STATUS_EASY_MISMATCH)
    field = itb_last_mismatch_field()
    call assert_string_eq(TEST_NAME, "mismatch field mode", field, "mode")
    call dst%destroy()
  end subroutine

  subroutine test_import_mismatch_mac()
    integer(itb_byte_kind), target, allocatable :: blob(:)
    type(itb_encryptor_t) :: dst
    integer(itb_status_kind) :: rc
    character(:), allocatable :: field

    call make_baseline_blob(blob)
    call new_itb_encryptor(dst, "blake3", 1024, "hmac-sha256", 1)
    call import_status(dst%raw_handle(), blob, rc)
    call assert_status_eq(TEST_NAME, "mac mismatch", rc, STATUS_EASY_MISMATCH)
    field = itb_last_mismatch_field()
    call assert_string_eq(TEST_NAME, "mismatch field mac", field, "mac")
    call dst%destroy()
  end subroutine

  subroutine test_import_malformed_json()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: bytes(:)
    integer(itb_status_kind) :: rc
    character(*), parameter :: BAD = "this is not json"
    integer :: i

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    allocate (bytes(len(BAD)))
    do i = 1, len(BAD)
      bytes(i) = int(iachar(BAD(i:i)), itb_byte_kind)
    end do
    call import_status(enc%raw_handle(), bytes, rc)
    call assert_status_eq(TEST_NAME, "import malformed json", rc, STATUS_EASY_MALFORMED)
    call enc%destroy()
  end subroutine

  subroutine test_import_too_new_version()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: bytes(:)
    integer(itb_status_kind) :: rc
    character(*), parameter :: BLOB_TXT = "{""v"":99,""kind"":""itb-easy""}"
    integer :: i

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    allocate (bytes(len(BLOB_TXT)))
    do i = 1, len(BLOB_TXT)
      bytes(i) = int(iachar(BLOB_TXT(i:i)), itb_byte_kind)
    end do
    call import_status(enc%raw_handle(), bytes, rc)
    call assert_status_eq(TEST_NAME, "import too new", rc, STATUS_EASY_VERSION_TOO_NEW)
    call enc%destroy()
  end subroutine

  subroutine test_import_wrong_kind()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: bytes(:)
    integer(itb_status_kind) :: rc
    character(*), parameter :: BLOB_TXT = "{""v"":1,""kind"":""not-itb-easy""}"
    integer :: i

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    allocate (bytes(len(BLOB_TXT)))
    do i = 1, len(BLOB_TXT)
      bytes(i) = int(iachar(BLOB_TXT(i:i)), itb_byte_kind)
    end do
    call import_status(enc%raw_handle(), bytes, rc)
    call assert_status_eq(TEST_NAME, "import wrong kind", rc, STATUS_EASY_MALFORMED)
    call enc%destroy()
  end subroutine

  subroutine test_mac_key_present()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), allocatable :: key(:)
    integer :: mi

    do mi = 1, size(MAC_NAMES)
      call new_itb_encryptor(enc, "blake3", 1024, trim(MAC_NAMES(mi)), 1)
      key = enc%mac_key()
      call assert_true(TEST_NAME, "mac_key non-empty", size(key) > 0)
      call enc%destroy()
    end do
  end subroutine

  ! Expected PRF key length per primitive. SipHash-2-4 has no PRF
  ! key (its keying material is consumed directly per pixel from
  ! seed components). Other primitives carry a fixed-size key.
  function expected_prf_key_len(name) result(n)
    character(*), intent(in) :: name
    integer :: n
    select case (trim(name))
    case ("areion256");  n = 32
    case ("areion512");  n = 64
    case ("siphash24");  n = 0
    case ("aescmac");    n = 16
    case ("blake2b256"); n = 32
    case ("blake2b512"); n = 64
    case ("blake2s");    n = 32
    case ("blake3");     n = 32
    case ("chacha20");   n = 32
    case default;        n = -1
    end select
  end function

  subroutine test_prf_key_lengths_per_primitive()
    type(itb_encryptor_t)  :: enc
    integer                :: hi, ki, kb, slot, sc
    integer(itb_byte_kind), allocatable :: key(:)
    logical                :: has_keys

    do hi = 1, size(HASHES)
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, WIDTHS(hi)) /= 0) cycle

        call new_itb_encryptor(enc, trim(HASHES(hi)), kb, "kmac256", 1)
        has_keys = enc%has_prf_keys()

        if (trim(HASHES(hi)) == "siphash24") then
          call assert_false(TEST_NAME, "siphash24 has_prf_keys", has_keys)
        else
          call assert_true(TEST_NAME, "non-siphash has_prf_keys", has_keys)
          sc = int(enc%seed_count())
          do slot = 0, sc - 1
            key = enc%prf_key(slot)
            call assert_int_eq(TEST_NAME, "prf_key length", &
                               expected_prf_key_len(trim(HASHES(hi))), size(key))
          end do
        end if
        call enc%destroy()
      end do
    end do
  end subroutine

  subroutine test_seed_components_lengths_per_key_bits()
    type(itb_encryptor_t) :: enc
    integer               :: hi, ki, kb, slot, sc
    integer(itb_u64_kind), allocatable :: comps(:)

    do hi = 1, size(HASHES)
      do ki = 1, size(CANDIDATE_KB)
        kb = CANDIDATE_KB(ki)
        if (mod(kb, WIDTHS(hi)) /= 0) cycle

        call new_itb_encryptor(enc, trim(HASHES(hi)), kb, "kmac256", 1)
        sc = int(enc%seed_count())
        do slot = 0, sc - 1
          comps = enc%seed_components(slot)
          ! Each seed component is 64-bit; component count * 64 == key_bits.
          call assert_int_eq(TEST_NAME, "seed_components count * 64 == key_bits", &
                             kb, size(comps) * 64)
        end do
        call enc%destroy()
      end do
    end do
  end subroutine

  subroutine test_seed_components_out_of_range()
    use itb_sys, only: itb_easy_seed_components_c
    type(itb_encryptor_t) :: enc
    integer(itb_u64_kind), target :: scratch(32)
    integer(c_int) :: out_count
    integer(c_int) :: rc

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call assert_int_eq(TEST_NAME, "seed_count Single == 3", 3, int(enc%seed_count()))

    ! slot=3 (out of range, valid range 0..2 for Single)
    out_count = 0
    rc = itb_easy_seed_components_c(enc%raw_handle(), 3_c_int, &
                                      c_loc(scratch), 32_c_int, out_count)
    call assert_status_eq(TEST_NAME, "seed_components slot=3 out of range", &
                          STATUS_BAD_INPUT, rc)

    ! slot=-1 (negative)
    out_count = 0
    rc = itb_easy_seed_components_c(enc%raw_handle(), -1_c_int, &
                                      c_loc(scratch), 32_c_int, out_count)
    call assert_status_eq(TEST_NAME, "seed_components slot=-1 negative", &
                          STATUS_BAD_INPUT, rc)

    call enc%destroy()
  end subroutine

end program test_easy_persistence
