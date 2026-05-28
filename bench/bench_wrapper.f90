! bench_wrapper.f90 -- format-deniability wrapper benchmarks for the
! Fortran binding.
!
! Mirrors the cross-binding wrapper bench shape. The outer-cipher
! palette covers every cipher in PRIMITIVES_CANONICAL order
! (areion256, areion512, blake2b256, blake2b512, blake2s, blake3,
! aescmac, siphash24, chacha20):
!
!   * wrapper only round-trip cases   ({ Wrap, WrapInPlace } per cipher)
!   * Message Single                  (4 modes x 2 dirs per cipher)
!   * Message Triple                  (4 modes x 2 dirs per cipher)
!   * Streaming Single                (4 modes x 2 dirs per cipher)
!   * Streaming Triple                (4 modes x 2 dirs per cipher)
!
! Streaming sub-bench inventory per direction = 4 modes per cipher
! (no `noaead-*-io` mode -- the Fortran binding has no
! unit-IO analogue for Non-AEAD streaming). Modes:
!
!   1. Streaming AEAD Easy IO-Driven       (MAC Authenticated)
!   2. Streaming AEAD Low-Level IO-Driven  (MAC Authenticated)
!   3. Streaming Easy User-Driven Loop     (No MAC)
!   4. Streaming Low-Level User-Driven Loop (No MAC)
!
! Message sub-bench modes:
!
!   1. Easy No MAC          (Single Message enc.encrypt)
!   2. Easy MAC Authenticated (Single Message enc.encrypt_auth)
!   3. Low-Level No MAC      (itb_encrypt with explicit seeds)
!   4. Low-Level MAC Authenticated (itb_encrypt_auth + MAC handle)
!
! Reproduction:
!
!   make bench
!   ./bench/bin/itb-bench-wrapper
!
! Environment variables: ITB_BENCH_FILTER, ITB_BENCH_MIN_SEC,
! ITB_NONCE_BITS, ITB_LOCKSEED -- shared with bench_common.f90.
!
! Memory discipline. All large payload arrays are `allocatable`,
! never stack-resident, mirroring the lessons from the existing
! bench_single / bench_triple binaries -- ifx's auto-reallocation
! temporaries land on the heap under -heap-arrays 0; gfortran
! stack-allocates by default. The 16 MiB single-message and 64 MiB
! streaming payloads exceed the default 8 MiB Linux stack limit.
!
! Pipeline discipline. Encrypt-direction cases run the full
!   inner-ITB-encrypt + Wrap_In_Place pipeline on each timed iteration;
!   decrypt-direction cases pre-build one pristine wire (one ITB
!   encrypt + one Wrap_In_Place) at setup, then refresh the working
!   wire from the pristine copy and run Unwrap_In_Place + ITB decrypt
!   on every timed iter. Mirrors wrapper/bench_test.go's
!   composeWire / pristineWire pattern. Setup-time pre-encryption of
!   the inner ciphertext for encrypt-direction cases would mask the
!   ITB encrypt cost — that is the bug the previous stub harness
!   exhibited (AES wrap XOR is fast enough that the missing inner
!   encrypt surfaced as 1.7x inflated MB/s on Single Message + AES).
!
! Streaming cases use the same 16 MiB payload as message cases (the
!   wrapper-bench harness does not parameterise streaming payload
!   independently here); they invoke the Single Message encrypt /
!   decrypt entry points so the per-iter cost reflects encrypt + wrap
!   end-to-end at one chunk granularity. The streaming-vs-message
!   distinction in the case names is preserved for cross-binding row
!   parity with the C / C++ / Ada / D wrapper benches.

module bench_wrapper_state
  use, intrinsic :: iso_fortran_env, only: int64, error_unit
  use itb_kinds,     only: itb_byte_kind
  use itb_seed,      only: itb_seed_t
  use itb_mac,       only: itb_mac_t
  use itb_encryptor, only: itb_encryptor_t
  implicit none
  private

  public :: case_state_t
  public :: case_kind_t
  public :: cases_state
  public :: cases_state_len
  public :: alloc_state
  public :: state_destroy_all

  ! Eight pipeline modes. Streaming cases reuse the same modes as
  ! message cases — the wire shape is identical at one-chunk
  ! granularity (16 MiB <= chunk_size). Wrapper Only cases are
  ! flagged separately via the kind tag.
  integer, parameter, public :: MODE_EASY_NOMAC_SINGLE = 1
  integer, parameter, public :: MODE_EASY_AUTH_SINGLE  = 2
  integer, parameter, public :: MODE_LOW_NOMAC_SINGLE  = 3
  integer, parameter, public :: MODE_LOW_AUTH_SINGLE   = 4
  integer, parameter, public :: MODE_EASY_NOMAC_TRIPLE = 5
  integer, parameter, public :: MODE_EASY_AUTH_TRIPLE  = 6
  integer, parameter, public :: MODE_LOW_NOMAC_TRIPLE  = 7
  integer, parameter, public :: MODE_LOW_AUTH_TRIPLE   = 8

  ! Bench-case kind selector. The same per-iter dispatcher routes
  ! through `mode` once kind == KIND_PIPELINE; Wrap-Only cases
  ! short-circuit to the local CTR XOR.
  integer, parameter, public :: KIND_WRAP_ONLY    = 0
  integer, parameter, public :: KIND_PIPELINE_ENC = 1
  integer, parameter, public :: KIND_PIPELINE_DEC = 2

  type :: case_kind_t
    integer :: kind = KIND_PIPELINE_ENC
    integer :: mode = MODE_EASY_NOMAC_SINGLE
  end type

  ! Per-case state. Encryptor + seeds + MAC are constructed lazily on
  ! first reference to the case (inside register_pipeline_state) so
  ! that unused modes do not consume libitb handles.
  type :: case_state_t
    integer                              :: cipher = 0
    integer                              :: kind   = KIND_PIPELINE_ENC
    integer                              :: mode   = MODE_EASY_NOMAC_SINGLE
    type(itb_encryptor_t)                :: enc_single
    type(itb_encryptor_t)                :: enc_triple
    type(itb_seed_t)                     :: seed_noise
    type(itb_seed_t)                     :: seed_data1, seed_data2, seed_data3
    type(itb_seed_t)                     :: seed_start1, seed_start2, seed_start3
    type(itb_mac_t)                      :: mac
    integer(itb_byte_kind), allocatable  :: outer_key(:)
    integer(itb_byte_kind), allocatable  :: payload(:)
    integer(itb_byte_kind), allocatable  :: pristine_wire(:)
    integer(itb_byte_kind), allocatable  :: work_buf(:)
  end type

  integer, parameter :: MAX_CASES = 320
  type(case_state_t), save :: cases_state(MAX_CASES)
  integer,            save :: cases_state_len = 0

contains

  function alloc_state() result(idx)
    integer :: idx
    if (cases_state_len >= MAX_CASES) then
      write (error_unit, "(A)") "bench_wrapper: state registry exhausted"
      error stop 1
    end if
    cases_state_len = cases_state_len + 1
    idx = cases_state_len
  end function

  subroutine state_destroy_all()
    integer :: i
    do i = 1, cases_state_len
      call cases_state(i)%enc_single%destroy()
      call cases_state(i)%enc_triple%destroy()
      call cases_state(i)%seed_noise%destroy()
      call cases_state(i)%seed_data1%destroy()
      call cases_state(i)%seed_data2%destroy()
      call cases_state(i)%seed_data3%destroy()
      call cases_state(i)%seed_start1%destroy()
      call cases_state(i)%seed_start2%destroy()
      call cases_state(i)%seed_start3%destroy()
      call cases_state(i)%mac%destroy()
      if (allocated(cases_state(i)%outer_key))     deallocate (cases_state(i)%outer_key)
      if (allocated(cases_state(i)%payload))       deallocate (cases_state(i)%payload)
      if (allocated(cases_state(i)%pristine_wire)) deallocate (cases_state(i)%pristine_wire)
      if (allocated(cases_state(i)%work_buf))      deallocate (cases_state(i)%work_buf)
    end do
    cases_state_len = 0
  end subroutine

end module bench_wrapper_state


program bench_wrapper
  use, intrinsic :: iso_fortran_env, only: int64, real64, output_unit
  use, intrinsic :: iso_c_binding
  use itb_kinds,    only: itb_byte_kind, itb_status_kind
  use itb_library,  only: itb_set_max_workers, itb_set_nonce_bits
  use itb_seed,     only: new_itb_seed
  use itb_mac,      only: new_itb_mac
  use itb_encryptor, only: new_itb_encryptor
  use itb_cipher,   only: itb_encrypt, itb_decrypt,                          &
                          itb_encrypt_auth, itb_decrypt_auth,                &
                          itb_encrypt_triple, itb_decrypt_triple,            &
                          itb_encrypt_auth_triple, itb_decrypt_auth_triple
  use itb_wrapper
  use itb_errors,   only: STATUS_OK
  use bench_common, only: PAYLOAD_16MB, env_lock_seed, env_nonce_bits,        &
                          env_filter, env_min_seconds,                         &
                          random_bytes, measure_one, bench_case_t,   &
                          contains_substr
  use bench_wrapper_state
  implicit none

  ! Cipher constants in canonical order.
  ! Full outer-keystream palette in PRIMITIVES_CANONICAL order
  ! (areion256, areion512, blake2b256, blake2b512, blake2s, blake3,
  ! aescmac, siphash24, chacha20).
  integer, parameter :: NUM_CIPHERS = 9
  integer, parameter :: CIPHERS(NUM_CIPHERS) = [                              &
      ITB_WRAPPER_CIPHER_AREION_256,                                           &
      ITB_WRAPPER_CIPHER_AREION_512,                                           &
      ITB_WRAPPER_CIPHER_BLAKE2B_256,                                          &
      ITB_WRAPPER_CIPHER_BLAKE2B_512,                                          &
      ITB_WRAPPER_CIPHER_BLAKE2S,                                              &
      ITB_WRAPPER_CIPHER_BLAKE3,                                               &
      ITB_WRAPPER_CIPHER_AES_128_CTR,                                          &
      ITB_WRAPPER_CIPHER_SIPHASH24,                                            &
      ITB_WRAPPER_CIPHER_CHACHA20]
  character(len=10), parameter :: CIPHER_NAMES(NUM_CIPHERS) = &
      [character(len=10) :: "areion256", "areion512", "blake2b256",           &
       "blake2b512", "blake2s", "blake3", "aescmac", "siphash24", "chacha20"]

  ! Per-mode label tables -- indexed by mode 1..4 in the canonical
  ! Easy-NoMAC / Easy-Auth / LowLevel-NoMAC / LowLevel-Auth order
  ! for messages. Streaming modes follow Streaming AEAD Easy IO,
  ! Streaming AEAD Low-Level IO, Streaming Easy UserLoop, Streaming
  ! Low-Level UserLoop.
  character(len=24), parameter :: MSG_MODE_NAMES(4) =                          &
      [character(len=24) ::                                                    &
        "easy_nomac",                                                          &
        "easy_auth",                                                           &
        "lowlevel_nomac",                                                      &
        "lowlevel_auth"]
  character(len=24), parameter :: STREAM_MODE_NAMES(4) =                       &
      [character(len=24) ::                                                    &
        "aead_easy_io",                                                        &
        "aead_lowlevel_io",                                                    &
        "easy_userloop",                                                       &
        "lowlevel_userloop"]

  character(*),         parameter :: PIPELINE_PRIMITIVE = "areion512"
  integer,              parameter :: PIPELINE_KEY_BITS  = 1024
  character(*),         parameter :: PIPELINE_MAC_NAME  = "hmac-blake3"

  integer(int64), parameter :: WRAPPER_PAYLOAD_BYTES = PAYLOAD_16MB
  ! Total cases: 34 per cipher (2 wrapper only + 8 msg-single +
  !   8 msg-triple + 8 stream-single + 8 stream-triple) across every cipher.
  integer, parameter :: TOTAL_CASES = 34 * NUM_CIPHERS

  integer               :: nonce_bits
  integer               :: ci, mode, dir
  real(real64)          :: min_secs
  character(:), allocatable :: flt
  type(bench_case_t)    :: one_case(1)
  character(len=256)    :: case_name
  logical               :: filter_active
  integer               :: n_selected, total_cases_count
  integer               :: g_mode, g_ci, g_dir

  nonce_bits = env_nonce_bits(128)
  call itb_set_max_workers(0)
  call itb_set_nonce_bits(nonce_bits)

  write (output_unit, "(A,I0,A,I0,A,A,A)") &
      "# wrapper payload_bytes=", WRAPPER_PAYLOAD_BYTES,                      &
      " ciphers=", NUM_CIPHERS,                                                &
      " lockseed=", merge("on ", "off", env_lock_seed())
  flush(output_unit)

  ! Read filter + min_seconds upfront so we can print the header.
  flt = env_filter()
  filter_active = (len(flt) > 0)
  min_secs = env_min_seconds()

  ! Count selected cases for the header line by iterating all case
  ! names and checking the filter -- no heavy allocation needed.
  n_selected = 0
  total_cases_count = TOTAL_CASES

  ! Wrapper Only: 2 per cipher.
  do g_ci = 1, NUM_CIPHERS
    case_name = "bench_wrapper_only_" // trim(CIPHER_NAMES(g_ci)) // "_wrap"
    if (.not. filter_active .or. contains_substr(trim(case_name), flt)) &
      n_selected = n_selected + 1
    case_name = "bench_wrapper_only_" // trim(CIPHER_NAMES(g_ci)) // "_inplace"
    if (.not. filter_active .or. contains_substr(trim(case_name), flt)) &
      n_selected = n_selected + 1
  end do
  ! Message Single, Triple; Streaming Single, Triple: 4 x 9 x 2 each.
  do g_mode = 1, 4
    do g_ci = 1, NUM_CIPHERS
      do g_dir = 1, 2
        case_name = "bench_message_single_" // trim(MSG_MODE_NAMES(g_mode)) &
            // "_" // trim(CIPHER_NAMES(g_ci)) // dir_suffix(g_dir)
        if (.not. filter_active .or. contains_substr(trim(case_name), flt)) &
          n_selected = n_selected + 1
        case_name = "bench_message_triple_" // trim(MSG_MODE_NAMES(g_mode)) &
            // "_" // trim(CIPHER_NAMES(g_ci)) // dir_suffix(g_dir)
        if (.not. filter_active .or. contains_substr(trim(case_name), flt)) &
          n_selected = n_selected + 1
        case_name = "bench_streaming_single_" // trim(STREAM_MODE_NAMES(g_mode)) &
            // "_" // trim(CIPHER_NAMES(g_ci)) // dir_suffix(g_dir)
        if (.not. filter_active .or. contains_substr(trim(case_name), flt)) &
          n_selected = n_selected + 1
        case_name = "bench_streaming_triple_" // trim(STREAM_MODE_NAMES(g_mode)) &
            // "_" // trim(CIPHER_NAMES(g_ci)) // dir_suffix(g_dir)
        if (.not. filter_active .or. contains_substr(trim(case_name), flt)) &
          n_selected = n_selected + 1
      end do
    end do
  end do

  write (output_unit, "(A,I0,A,I0,A,F0.3)") &
      "# benchmarks=", n_selected,                                             &
      " payload_bytes=", WRAPPER_PAYLOAD_BYTES,                                &
      " min_seconds=", min_secs
  flush(output_unit)

  ! Lazy loop: for each (cipher, kind, mode, dir) tuple, register one
  ! case, measure it, destroy state, then proceed to the next.
  ! Wrapper Only — 2 per cipher.
  do ci = 1, NUM_CIPHERS
    case_name = "bench_wrapper_only_" // trim(CIPHER_NAMES(ci)) // "_wrap"
    if (.not. filter_active .or. contains_substr(trim(case_name), flt)) then
      call register_wrapper_only(one_case(1), trim(case_name), CIPHERS(ci), .false.)
      call measure_one(one_case(1), min_secs)
      call state_destroy_all()
    end if
    case_name = "bench_wrapper_only_" // trim(CIPHER_NAMES(ci)) // "_inplace"
    if (.not. filter_active .or. contains_substr(trim(case_name), flt)) then
      call register_wrapper_only(one_case(1), trim(case_name), CIPHERS(ci), .true.)
      call measure_one(one_case(1), min_secs)
      call state_destroy_all()
    end if
  end do

  ! Message Single: modes 1-4, each cipher, each dir.
  do mode = 1, 4
    do ci = 1, NUM_CIPHERS
      do dir = 1, 2
        case_name = "bench_message_single_" // trim(MSG_MODE_NAMES(mode)) &
            // "_" // trim(CIPHER_NAMES(ci)) // dir_suffix(dir)
        if (.not. filter_active .or. contains_substr(trim(case_name), flt)) then
          call register_pipeline(one_case(1), trim(case_name), CIPHERS(ci), &
                                  msg_mode_to_modeid(mode, .false.), dir)
          call measure_one(one_case(1), min_secs)
          call state_destroy_all()
        end if
      end do
    end do
  end do

  ! Message Triple: modes 1-4, each cipher, each dir.
  do mode = 1, 4
    do ci = 1, NUM_CIPHERS
      do dir = 1, 2
        case_name = "bench_message_triple_" // trim(MSG_MODE_NAMES(mode)) &
            // "_" // trim(CIPHER_NAMES(ci)) // dir_suffix(dir)
        if (.not. filter_active .or. contains_substr(trim(case_name), flt)) then
          call register_pipeline(one_case(1), trim(case_name), CIPHERS(ci), &
                                  msg_mode_to_modeid(mode, .true.), dir)
          call measure_one(one_case(1), min_secs)
          call state_destroy_all()
        end if
      end do
    end do
  end do

  ! Streaming Single: modes 1-4, each cipher, each dir.
  do mode = 1, 4
    do ci = 1, NUM_CIPHERS
      do dir = 1, 2
        case_name = "bench_streaming_single_" // trim(STREAM_MODE_NAMES(mode)) &
            // "_" // trim(CIPHER_NAMES(ci)) // dir_suffix(dir)
        if (.not. filter_active .or. contains_substr(trim(case_name), flt)) then
          call register_pipeline(one_case(1), trim(case_name), CIPHERS(ci), &
                                  stream_mode_to_modeid(mode, .false.), dir)
          call measure_one(one_case(1), min_secs)
          call state_destroy_all()
        end if
      end do
    end do
  end do

  ! Streaming Triple: modes 1-4, each cipher, each dir.
  do mode = 1, 4
    do ci = 1, NUM_CIPHERS
      do dir = 1, 2
        case_name = "bench_streaming_triple_" // trim(STREAM_MODE_NAMES(mode)) &
            // "_" // trim(CIPHER_NAMES(ci)) // dir_suffix(dir)
        if (.not. filter_active .or. contains_substr(trim(case_name), flt)) then
          call register_pipeline(one_case(1), trim(case_name), CIPHERS(ci), &
                                  stream_mode_to_modeid(mode, .true.), dir)
          call measure_one(one_case(1), min_secs)
          call state_destroy_all()
        end if
      end do
    end do
  end do

contains

  ! ----------------------------------------------------------------
  ! Per-iter callables.
  ! ----------------------------------------------------------------

  ! Wrapper Only Wrap-alloc: one fresh `wire(:)` allocation per call.
  subroutine run_wrap_alloc(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_byte_kind), allocatable :: wire(:)
    integer(itb_status_kind) :: rc
    do i = 1_int64, iters
      call itb_wrap(cases_state(case_idx)%cipher,                              &
                     cases_state(case_idx)%outer_key,                          &
                     cases_state(case_idx)%payload, wire, rc)
      if (rc /= STATUS_OK) error stop 1
      if (allocated(wire)) deallocate (wire)
    end do
  end subroutine

  ! Wrapper Only WrapInPlace: blob is mutated in place; nonce is
  ! returned in a separately-allocated buffer. Each iteration first
  ! restores the blob from a fresh CSPRNG sample (so the per-call
  ! XOR overwrites a fresh buffer rather than the previous wrap's
  ! output -- the bench measures one wrap, not a chain).
  subroutine run_wrap_in_place(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i, j, n_bytes
    integer(itb_byte_kind), allocatable :: nonce(:)
    integer(itb_byte_kind), allocatable :: blob(:)
    integer(itb_status_kind) :: rc

    n_bytes = int(size(cases_state(case_idx)%payload), int64)
    allocate (blob(n_bytes))
    do i = 1_int64, iters
      do j = 1_int64, n_bytes
        blob(j) = cases_state(case_idx)%payload(j)
      end do
      call itb_wrap_in_place(cases_state(case_idx)%cipher,                     &
                              cases_state(case_idx)%outer_key,                 &
                              blob, nonce, rc)
      if (rc /= STATUS_OK) error stop 1
      if (allocated(nonce)) deallocate (nonce)
    end do
    deallocate (blob)
  end subroutine

  ! ----------------------------------------------------------------
  ! Pipeline encrypt-direction iter.
  !
  ! Each iteration: ITB encrypt (matching the case's mode) → wrap
  ! the inner ciphertext into a fresh on-wire buffer.
  ! ----------------------------------------------------------------
  subroutine run_pipeline_encrypt(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_byte_kind), allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: nonce(:)
    integer(itb_status_kind) :: rc

    do i = 1_int64, iters
      ! Stage 1 — inner ITB encrypt. Each branch produces a freshly-
      ! allocated `ct(:)` array sized to the inner ciphertext length.
      select case (cases_state(case_idx)%mode)
      case (MODE_EASY_NOMAC_SINGLE)
        ct = cases_state(case_idx)%enc_single%encrypt(cases_state(case_idx)%payload)
      case (MODE_EASY_AUTH_SINGLE)
        ct = cases_state(case_idx)%enc_single%encrypt_auth(cases_state(case_idx)%payload)
      case (MODE_LOW_NOMAC_SINGLE)
        ct = itb_encrypt(cases_state(case_idx)%seed_noise,                    &
                          cases_state(case_idx)%seed_data1,                    &
                          cases_state(case_idx)%seed_start1,                   &
                          cases_state(case_idx)%payload)
      case (MODE_LOW_AUTH_SINGLE)
        ct = itb_encrypt_auth(cases_state(case_idx)%seed_noise,               &
                               cases_state(case_idx)%seed_data1,               &
                               cases_state(case_idx)%seed_start1,              &
                               cases_state(case_idx)%mac,                      &
                               cases_state(case_idx)%payload)
      case (MODE_EASY_NOMAC_TRIPLE)
        ct = cases_state(case_idx)%enc_triple%encrypt(cases_state(case_idx)%payload)
      case (MODE_EASY_AUTH_TRIPLE)
        ct = cases_state(case_idx)%enc_triple%encrypt_auth(cases_state(case_idx)%payload)
      case (MODE_LOW_NOMAC_TRIPLE)
        ct = itb_encrypt_triple(cases_state(case_idx)%seed_noise,             &
                                 cases_state(case_idx)%seed_data1,             &
                                 cases_state(case_idx)%seed_data2,             &
                                 cases_state(case_idx)%seed_data3,             &
                                 cases_state(case_idx)%seed_start1,            &
                                 cases_state(case_idx)%seed_start2,            &
                                 cases_state(case_idx)%seed_start3,            &
                                 cases_state(case_idx)%payload)
      case (MODE_LOW_AUTH_TRIPLE)
        ct = itb_encrypt_auth_triple(cases_state(case_idx)%seed_noise,        &
                                      cases_state(case_idx)%seed_data1,        &
                                      cases_state(case_idx)%seed_data2,        &
                                      cases_state(case_idx)%seed_data3,        &
                                      cases_state(case_idx)%seed_start1,       &
                                      cases_state(case_idx)%seed_start2,       &
                                      cases_state(case_idx)%seed_start3,       &
                                      cases_state(case_idx)%mac,               &
                                      cases_state(case_idx)%payload)
      case default
        error stop "run_pipeline_encrypt: unknown mode"
      end select

      ! Stage 2 — wrap in place. ct is mutated; nonce is returned in
      ! a freshly-allocated buffer. Both arrays are released after
      ! the iter.
      call itb_wrap_in_place(cases_state(case_idx)%cipher,                     &
                              cases_state(case_idx)%outer_key,                 &
                              ct, nonce, rc)
      if (rc /= STATUS_OK) error stop 1

      if (allocated(ct))    deallocate (ct)
      if (allocated(nonce)) deallocate (nonce)
    end do
  end subroutine

  ! ----------------------------------------------------------------
  ! Pipeline decrypt-direction iter.
  !
  ! Setup pre-builds one pristine wire (one ITB encrypt + one
  ! Wrap_In_Place) into cases_state(case_idx)%pristine_wire. Each
  ! timed iter refreshes a working copy from the pristine wire,
  ! unwraps in place, and runs the matching ITB decrypt against the
  ! recovered inner ciphertext.
  ! ----------------------------------------------------------------
  subroutine run_pipeline_decrypt(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i, j
    integer(itb_byte_kind), allocatable :: pt(:)
    integer :: wire_len
    integer :: body_first, nonce_size
    integer(itb_status_kind) :: rc

    wire_len = size(cases_state(case_idx)%pristine_wire)
    if (.not. allocated(cases_state(case_idx)%work_buf) .or.                    &
        size(cases_state(case_idx)%work_buf) < wire_len) then
      if (allocated(cases_state(case_idx)%work_buf)) then
        deallocate (cases_state(case_idx)%work_buf)
      end if
      allocate (cases_state(case_idx)%work_buf(wire_len))
    end if
    call itb_wrapper_nonce_size(cases_state(case_idx)%cipher, nonce_size, rc)
    if (rc /= STATUS_OK) error stop 1

    do i = 1_int64, iters
      ! Refresh the working wire from the pristine pre-built wire.
      ! Unwrap_In_Place mutates the wire's body bytes; the pristine
      ! buffer must remain pristine across iters.
      do j = 1, wire_len
        cases_state(case_idx)%work_buf(j) =                                    &
          cases_state(case_idx)%pristine_wire(j)
      end do

      call itb_unwrap_in_place(cases_state(case_idx)%cipher,                   &
                                cases_state(case_idx)%outer_key,               &
                                cases_state(case_idx)%work_buf(1:wire_len),    &
                                body_first, rc)
      if (rc /= STATUS_OK) error stop 1

      ! ITB decrypt against the recovered inner ciphertext. body_first
      ! is the 1-based offset of the first inner-ciphertext byte;
      ! the recovered inner CT is work_buf(body_first .. wire_len).
      select case (cases_state(case_idx)%mode)
      case (MODE_EASY_NOMAC_SINGLE)
        pt = cases_state(case_idx)%enc_single%decrypt(                         &
               cases_state(case_idx)%work_buf(body_first:wire_len))
      case (MODE_EASY_AUTH_SINGLE)
        pt = cases_state(case_idx)%enc_single%decrypt_auth(                    &
               cases_state(case_idx)%work_buf(body_first:wire_len))
      case (MODE_LOW_NOMAC_SINGLE)
        pt = itb_decrypt(cases_state(case_idx)%seed_noise,                    &
                          cases_state(case_idx)%seed_data1,                    &
                          cases_state(case_idx)%seed_start1,                   &
                          cases_state(case_idx)%work_buf(body_first:wire_len))
      case (MODE_LOW_AUTH_SINGLE)
        pt = itb_decrypt_auth(cases_state(case_idx)%seed_noise,               &
                               cases_state(case_idx)%seed_data1,               &
                               cases_state(case_idx)%seed_start1,              &
                               cases_state(case_idx)%mac,                      &
                               cases_state(case_idx)%work_buf(body_first:wire_len))
      case (MODE_EASY_NOMAC_TRIPLE)
        pt = cases_state(case_idx)%enc_triple%decrypt(                         &
               cases_state(case_idx)%work_buf(body_first:wire_len))
      case (MODE_EASY_AUTH_TRIPLE)
        pt = cases_state(case_idx)%enc_triple%decrypt_auth(                    &
               cases_state(case_idx)%work_buf(body_first:wire_len))
      case (MODE_LOW_NOMAC_TRIPLE)
        pt = itb_decrypt_triple(cases_state(case_idx)%seed_noise,             &
                                 cases_state(case_idx)%seed_data1,             &
                                 cases_state(case_idx)%seed_data2,             &
                                 cases_state(case_idx)%seed_data3,             &
                                 cases_state(case_idx)%seed_start1,            &
                                 cases_state(case_idx)%seed_start2,            &
                                 cases_state(case_idx)%seed_start3,            &
                                 cases_state(case_idx)%work_buf(body_first:wire_len))
      case (MODE_LOW_AUTH_TRIPLE)
        pt = itb_decrypt_auth_triple(cases_state(case_idx)%seed_noise,        &
                                      cases_state(case_idx)%seed_data1,        &
                                      cases_state(case_idx)%seed_data2,        &
                                      cases_state(case_idx)%seed_data3,        &
                                      cases_state(case_idx)%seed_start1,       &
                                      cases_state(case_idx)%seed_start2,       &
                                      cases_state(case_idx)%seed_start3,       &
                                      cases_state(case_idx)%mac,               &
                                      cases_state(case_idx)%work_buf(body_first:wire_len))
      case default
        error stop "run_pipeline_decrypt: unknown mode"
      end select

      if (size(pt) /= size(cases_state(case_idx)%payload))                     &
        error stop "run_pipeline_decrypt: plaintext length mismatch"
      if (allocated(pt)) deallocate (pt)
    end do
    ! nonce_size is not consumed inside the iter loop — kept here as
    ! a sanity-check return from the cipher metadata probe so a bad
    ! handle / cipher constant trips at construction time rather than
    ! mid-iter.
    if (nonce_size <= 0) error stop "run_pipeline_decrypt: bad nonce size"
  end subroutine

  ! ----------------------------------------------------------------
  ! Case construction helpers
  ! ----------------------------------------------------------------

  ! Builds the encryptor / seeds / MAC bound to a per-case mode plus
  ! the pristine wire (decrypt-direction only). Encrypt-direction
  ! cases skip the wire pre-build but still construct the underlying
  ! Easy / Low-Level state — the timed loop runs ITB encrypt every
  ! iter against that state.
  subroutine make_pipeline_state(cipher, mode, kind, idx)
    integer,        intent(in)  :: cipher
    integer,        intent(in)  :: mode
    integer,        intent(in)  :: kind
    integer,        intent(out) :: idx
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_byte_kind), allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: nonce(:)
    integer(itb_byte_kind), target :: mac_key_view(32)
    integer(itb_status_kind) :: rc
    integer(int64), allocatable :: scratch(:)
    integer(int64) :: i
    integer :: nonce_size, wire_total
    integer :: k

    idx = alloc_state()
    cases_state(idx)%cipher = cipher
    cases_state(idx)%kind   = kind
    cases_state(idx)%mode   = mode

    call itb_wrapper_generate_key(cipher, key, rc)
    if (rc /= STATUS_OK) error stop 1
    cases_state(idx)%outer_key = key
    deallocate (key)

    allocate (scratch(WRAPPER_PAYLOAD_BYTES))
    call random_bytes(scratch, WRAPPER_PAYLOAD_BYTES)
    allocate (cases_state(idx)%payload(WRAPPER_PAYLOAD_BYTES))
    do i = 1_int64, WRAPPER_PAYLOAD_BYTES
      cases_state(idx)%payload(i) = int(scratch(i), itb_byte_kind)
    end do
    deallocate (scratch)

    ! Build the encryptor / seed / MAC state matching `mode`. Each
    ! mode constructs only the state it needs to keep libitb handle
    ! count proportional to the live bench cases.
    select case (mode)
    case (MODE_EASY_NOMAC_SINGLE, MODE_EASY_AUTH_SINGLE)
      call new_itb_encryptor(cases_state(idx)%enc_single,                      &
                              PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS,            &
                              PIPELINE_MAC_NAME, 1)
      if (env_lock_seed()) call cases_state(idx)%enc_single%set_lock_seed(1)
    case (MODE_EASY_NOMAC_TRIPLE, MODE_EASY_AUTH_TRIPLE)
      call new_itb_encryptor(cases_state(idx)%enc_triple,                      &
                              PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS,            &
                              PIPELINE_MAC_NAME, 3)
      if (env_lock_seed()) call cases_state(idx)%enc_triple%set_lock_seed(1)
    case (MODE_LOW_NOMAC_SINGLE)
      call new_itb_seed(cases_state(idx)%seed_noise,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_data1,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_start1,                         &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
    case (MODE_LOW_AUTH_SINGLE)
      call new_itb_seed(cases_state(idx)%seed_noise,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_data1,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_start1,                         &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      ! Pseudo-random MAC key derived from the per-case payload's
      ! first 32 bytes (any non-uniform 32-byte sequence works for
      ! a throughput bench).
      do k = 1, 32
        mac_key_view(k) = cases_state(idx)%payload(k)
      end do
      call new_itb_mac(cases_state(idx)%mac, PIPELINE_MAC_NAME, mac_key_view)
    case (MODE_LOW_NOMAC_TRIPLE)
      call new_itb_seed(cases_state(idx)%seed_noise,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_data1,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_data2,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_data3,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_start1,                         &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_start2,                         &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_start3,                         &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
    case (MODE_LOW_AUTH_TRIPLE)
      call new_itb_seed(cases_state(idx)%seed_noise,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_data1,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_data2,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_data3,                          &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_start1,                         &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_start2,                         &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      call new_itb_seed(cases_state(idx)%seed_start3,                         &
                         PIPELINE_PRIMITIVE, PIPELINE_KEY_BITS)
      do k = 1, 32
        mac_key_view(k) = cases_state(idx)%payload(k)
      end do
      call new_itb_mac(cases_state(idx)%mac, PIPELINE_MAC_NAME, mac_key_view)
    case default
      error stop "make_pipeline_state: unknown mode"
    end select

    ! Decrypt-direction cases pre-build one pristine wire outside
    ! the timed loop. The encrypt-direction path leaves
    ! pristine_wire unallocated.
    if (kind /= KIND_PIPELINE_DEC) return

    select case (mode)
    case (MODE_EASY_NOMAC_SINGLE)
      ct = cases_state(idx)%enc_single%encrypt(cases_state(idx)%payload)
    case (MODE_EASY_AUTH_SINGLE)
      ct = cases_state(idx)%enc_single%encrypt_auth(cases_state(idx)%payload)
    case (MODE_LOW_NOMAC_SINGLE)
      ct = itb_encrypt(cases_state(idx)%seed_noise,                           &
                        cases_state(idx)%seed_data1,                           &
                        cases_state(idx)%seed_start1,                          &
                        cases_state(idx)%payload)
    case (MODE_LOW_AUTH_SINGLE)
      ct = itb_encrypt_auth(cases_state(idx)%seed_noise,                      &
                             cases_state(idx)%seed_data1,                      &
                             cases_state(idx)%seed_start1,                     &
                             cases_state(idx)%mac,                             &
                             cases_state(idx)%payload)
    case (MODE_EASY_NOMAC_TRIPLE)
      ct = cases_state(idx)%enc_triple%encrypt(cases_state(idx)%payload)
    case (MODE_EASY_AUTH_TRIPLE)
      ct = cases_state(idx)%enc_triple%encrypt_auth(cases_state(idx)%payload)
    case (MODE_LOW_NOMAC_TRIPLE)
      ct = itb_encrypt_triple(cases_state(idx)%seed_noise,                    &
                               cases_state(idx)%seed_data1,                    &
                               cases_state(idx)%seed_data2,                    &
                               cases_state(idx)%seed_data3,                    &
                               cases_state(idx)%seed_start1,                   &
                               cases_state(idx)%seed_start2,                   &
                               cases_state(idx)%seed_start3,                   &
                               cases_state(idx)%payload)
    case (MODE_LOW_AUTH_TRIPLE)
      ct = itb_encrypt_auth_triple(cases_state(idx)%seed_noise,               &
                                    cases_state(idx)%seed_data1,               &
                                    cases_state(idx)%seed_data2,               &
                                    cases_state(idx)%seed_data3,               &
                                    cases_state(idx)%seed_start1,              &
                                    cases_state(idx)%seed_start2,              &
                                    cases_state(idx)%seed_start3,              &
                                    cases_state(idx)%mac,                      &
                                    cases_state(idx)%payload)
    end select

    call itb_wrap_in_place(cipher, cases_state(idx)%outer_key,                 &
                            ct, nonce, rc)
    if (rc /= STATUS_OK) error stop 1
    nonce_size = size(nonce)
    wire_total = nonce_size + size(ct)
    allocate (cases_state(idx)%pristine_wire(wire_total))
    cases_state(idx)%pristine_wire(1:nonce_size) = nonce(1:nonce_size)
    cases_state(idx)%pristine_wire(nonce_size + 1:wire_total) = ct(1:size(ct))
    deallocate (ct)
    deallocate (nonce)
  end subroutine

  pure function dir_suffix(dir) result(s)
    integer, intent(in)       :: dir
    character(:), allocatable :: s
    if (dir == 1) then
      s = "_encrypt"
    else
      s = "_decrypt"
    end if
  end function

  ! Maps a 1..4 message mode index to the canonical mode id; `triple`
  ! selects the Triple Ouroboros parallel of each Single mode.
  pure function msg_mode_to_modeid(mode, triple) result(id)
    integer, intent(in) :: mode
    logical, intent(in) :: triple
    integer             :: id
    if (.not. triple) then
      select case (mode)
      case (1); id = MODE_EASY_NOMAC_SINGLE
      case (2); id = MODE_EASY_AUTH_SINGLE
      case (3); id = MODE_LOW_NOMAC_SINGLE
      case (4); id = MODE_LOW_AUTH_SINGLE
      case default; id = MODE_EASY_NOMAC_SINGLE
      end select
    else
      select case (mode)
      case (1); id = MODE_EASY_NOMAC_TRIPLE
      case (2); id = MODE_EASY_AUTH_TRIPLE
      case (3); id = MODE_LOW_NOMAC_TRIPLE
      case (4); id = MODE_LOW_AUTH_TRIPLE
      case default; id = MODE_EASY_NOMAC_TRIPLE
      end select
    end if
  end function

  ! Streaming AEAD modes map to MAC Authenticated message modes
  ! (Easy AEAD IO -> Easy MAC Authenticated; Low-Level AEAD IO ->
  ! Low-Level MAC Authenticated). Streaming No MAC User-Driven Loop
  ! modes map to the matching No MAC message modes.
  pure function stream_mode_to_modeid(mode, triple) result(id)
    integer, intent(in) :: mode
    logical, intent(in) :: triple
    integer             :: id
    if (.not. triple) then
      select case (mode)
      case (1); id = MODE_EASY_AUTH_SINGLE     ! aead_easy_io
      case (2); id = MODE_LOW_AUTH_SINGLE      ! aead_lowlevel_io
      case (3); id = MODE_EASY_NOMAC_SINGLE    ! easy_userloop
      case (4); id = MODE_LOW_NOMAC_SINGLE     ! lowlevel_userloop
      case default; id = MODE_EASY_AUTH_SINGLE
      end select
    else
      select case (mode)
      case (1); id = MODE_EASY_AUTH_TRIPLE
      case (2); id = MODE_LOW_AUTH_TRIPLE
      case (3); id = MODE_EASY_NOMAC_TRIPLE
      case (4); id = MODE_LOW_NOMAC_TRIPLE
      case default; id = MODE_EASY_AUTH_TRIPLE
      end select
    end if
  end function

  subroutine register_wrapper_only(c, label, cipher, in_place)
    type(bench_case_t), intent(out) :: c
    character(*),       intent(in)  :: label
    integer,            intent(in)  :: cipher
    logical,            intent(in)  :: in_place
    integer :: idx
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_status_kind) :: rc
    integer(int64), allocatable :: scratch(:)
    integer(int64) :: i

    idx = alloc_state()
    cases_state(idx)%cipher = cipher
    cases_state(idx)%kind   = KIND_WRAP_ONLY

    call itb_wrapper_generate_key(cipher, key, rc)
    if (rc /= STATUS_OK) error stop 1
    cases_state(idx)%outer_key = key
    deallocate (key)

    allocate (scratch(WRAPPER_PAYLOAD_BYTES))
    call random_bytes(scratch, WRAPPER_PAYLOAD_BYTES)
    allocate (cases_state(idx)%payload(WRAPPER_PAYLOAD_BYTES))
    do i = 1_int64, WRAPPER_PAYLOAD_BYTES
      cases_state(idx)%payload(i) = int(scratch(i), itb_byte_kind)
    end do
    deallocate (scratch)

    c%name = label
    c%case_idx = idx
    c%payload_bytes = WRAPPER_PAYLOAD_BYTES
    if (in_place) then
      c%run => run_wrap_in_place
    else
      c%run => run_wrap_alloc
    end if
  end subroutine

  subroutine register_pipeline(c, label, cipher, mode, dir)
    type(bench_case_t), intent(out) :: c
    character(*),       intent(in)  :: label
    integer,            intent(in)  :: cipher
    integer,            intent(in)  :: mode
    integer,            intent(in)  :: dir
    integer :: idx
    integer :: kind

    if (dir == 1) then
      kind = KIND_PIPELINE_ENC
    else
      kind = KIND_PIPELINE_DEC
    end if

    call make_pipeline_state(cipher, mode, kind, idx)

    c%name = label
    c%case_idx = idx
    c%payload_bytes = WRAPPER_PAYLOAD_BYTES
    if (kind == KIND_PIPELINE_ENC) then
      c%run => run_pipeline_encrypt
    else
      c%run => run_pipeline_decrypt
    end if
  end subroutine

end program bench_wrapper
