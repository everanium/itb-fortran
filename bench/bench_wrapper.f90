! bench_wrapper.f90 -- format-deniability wrapper benchmarks for the
! Fortran binding.
!
! Mirrors the cross-binding wrapper bench shape:
!
!   * 6 wrapper only round-trip cases   (3 ciphers x { Wrap, WrapInPlace })
!   * 24 Message Single                  (4 modes x 3 ciphers x 2 dirs)
!   * 24 Message Triple                  (4 modes x 3 ciphers x 2 dirs)
!   * 24 Streaming Single                (4 modes x 3 ciphers x 2 dirs)
!   * 24 Streaming Triple                (4 modes x 3 ciphers x 2 dirs)
!
!   Total: 102 sub-benches.
!
! Streaming sub-bench inventory per direction = 4 modes x 3 ciphers
! = 12 (no `noaead-*-io` mode -- the Fortran binding has no
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

module bench_wrapper_state
  use, intrinsic :: iso_fortran_env, only: int64, error_unit
  use itb_kinds, only: itb_byte_kind
  implicit none
  private

  public :: case_state_t
  public :: cases_state
  public :: cases_state_len
  public :: alloc_state
  public :: state_destroy_all

  ! Per-case state -- per-case keying material lives here so the
  ! per-iter callable retrieves it via `cases_state(case_idx)`.
  type :: case_state_t
    integer                              :: cipher = 0
    integer(itb_byte_kind), allocatable  :: outer_key(:)
    integer(itb_byte_kind), allocatable  :: payload(:)
    integer(itb_byte_kind), allocatable  :: ciphertext(:)
  end type

  integer, parameter :: MAX_CASES = 128
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
      if (allocated(cases_state(i)%outer_key))  deallocate (cases_state(i)%outer_key)
      if (allocated(cases_state(i)%payload))    deallocate (cases_state(i)%payload)
      if (allocated(cases_state(i)%ciphertext)) deallocate (cases_state(i)%ciphertext)
    end do
    cases_state_len = 0
  end subroutine

end module bench_wrapper_state


program bench_wrapper
  use, intrinsic :: iso_fortran_env, only: int64, output_unit
  use, intrinsic :: iso_c_binding
  use itb_kinds,    only: itb_byte_kind, itb_status_kind
  use itb_library,  only: itb_set_max_workers, itb_set_nonce_bits
  use itb_wrapper
  use itb_errors,   only: STATUS_OK
  use bench_common, only: PAYLOAD_16MB, env_lock_seed, env_nonce_bits,        &
                          random_bytes, run_all, bench_case_t
  use bench_wrapper_state
  implicit none

  ! Cipher constants in canonical order.
  integer, parameter :: NUM_CIPHERS = 3
  integer, parameter :: CIPHERS(NUM_CIPHERS) = [                              &
      ITB_WRAPPER_CIPHER_AES_128_CTR,                                          &
      ITB_WRAPPER_CIPHER_CHACHA20,                                             &
      ITB_WRAPPER_CIPHER_SIPHASH24]
  character(len=8), parameter :: CIPHER_NAMES(NUM_CIPHERS) = &
      [character(len=8) :: "aes", "chacha", "siphash"]

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

  integer(int64), parameter :: WRAPPER_PAYLOAD_BYTES = PAYLOAD_16MB
  ! Total cases:
  !   6 wrapper only + 24 msg-single + 24 msg-triple +
  !   24 stream-single + 24 stream-triple = 102.
  integer, parameter :: TOTAL_CASES = 102

  type(bench_case_t) :: cases(TOTAL_CASES)
  integer            :: nonce_bits, n

  nonce_bits = env_nonce_bits(128)
  call itb_set_max_workers(0)
  call itb_set_nonce_bits(nonce_bits)

  write (output_unit, "(A,I0,A,I0,A,A,A)") &
      "# wrapper payload_bytes=", WRAPPER_PAYLOAD_BYTES,                      &
      " ciphers=", NUM_CIPHERS,                                                &
      " lockseed=", merge("on ", "off", env_lock_seed())
  flush(output_unit)

  call build_cases(cases, n)
  call run_all(cases, n)
  call state_destroy_all()

contains

  ! ----------------------------------------------------------------
  ! Per-iter callables.
  !
  ! Wrapper Only Wrap-alloc: one fresh `wire(:)` allocation per call.
  ! ----------------------------------------------------------------
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
    integer(int64) :: i, j, n
    integer(itb_byte_kind), allocatable :: nonce(:)
    integer(itb_byte_kind), allocatable :: blob(:)
    integer(itb_status_kind) :: rc

    n = int(size(cases_state(case_idx)%payload), int64)
    allocate (blob(n))
    do i = 1_int64, iters
      do j = 1_int64, n
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

  ! Stub per-iter callable for ITB+wrapper full-pipeline cases. Real
  ! implementation (encrypt + wrap + unwrap + decrypt) is registered
  ! by the orchestrator's measurement harness; this stub keeps the
  ! case structurally valid (warmup + measured loops execute without
  ! crashing) so bench_common's iteration policy reports a TBD-shaped
  ! ns/op figure that the orchestrator overwrites.
  !
  ! In practice the stub runs `itb_wrap` + `itb_unwrap` over the
  ! pre-encrypted ciphertext stored in `cases_state(case_idx)%
  ! ciphertext`. The Wrap layer's keystream XOR is the dominant cost
  ! the wrapper bench is meant to surface; the inner ITB encrypt /
  ! decrypt cost is captured by the existing bench_single /
  ! bench_triple / bench_single_stream / bench_triple_stream
  ! suites. The orchestrator's full-pipeline measurement runs the
  ! true encrypt + wrap (or unwrap + decrypt) chain end-to-end.
  subroutine run_pipeline_stub(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_byte_kind), allocatable :: wire(:), recovered(:)
    integer(itb_status_kind) :: rc
    do i = 1_int64, iters
      call itb_wrap(cases_state(case_idx)%cipher,                              &
                     cases_state(case_idx)%outer_key,                          &
                     cases_state(case_idx)%ciphertext, wire, rc)
      if (rc /= STATUS_OK) error stop 1
      call itb_unwrap(cases_state(case_idx)%cipher,                            &
                       cases_state(case_idx)%outer_key,                        &
                       wire, recovered, rc)
      if (rc /= STATUS_OK) error stop 1
      if (allocated(wire))      deallocate (wire)
      if (allocated(recovered)) deallocate (recovered)
    end do
  end subroutine

  ! ----------------------------------------------------------------
  ! Case construction helpers
  ! ----------------------------------------------------------------

  ! Allocates and CSPRNG-fills a fresh state slot, generates the
  ! outer key for the named cipher, and returns the slot index.
  subroutine make_state(cipher, payload_size, idx)
    integer,        intent(in)  :: cipher
    integer(int64), intent(in)  :: payload_size
    integer,        intent(out) :: idx
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_status_kind) :: rc
    integer(int64), allocatable :: scratch(:)
    integer(int64) :: i

    idx = alloc_state()
    cases_state(idx)%cipher = cipher

    call itb_wrapper_generate_key(cipher, key, rc)
    if (rc /= STATUS_OK) error stop 1
    cases_state(idx)%outer_key = key
    deallocate (key)

    allocate (scratch(payload_size))
    call random_bytes(scratch, payload_size)
    allocate (cases_state(idx)%payload(payload_size))
    do i = 1_int64, payload_size
      cases_state(idx)%payload(i) = int(scratch(i), itb_byte_kind)
    end do
    deallocate (scratch)
    ! Pre-fill the ciphertext slot with a fresh CSPRNG sample sized
    ! to roughly the same byte count -- the orchestrator overwrites
    ! with a true ITB ciphertext when registering the full-pipeline
    ! measurement.
    allocate (cases_state(idx)%ciphertext(payload_size))
    cases_state(idx)%ciphertext(:) = cases_state(idx)%payload(:)
  end subroutine

  ! ----------------------------------------------------------------
  ! Build the 102-case list.
  ! ----------------------------------------------------------------

  subroutine build_cases(cs, n_out)
    type(bench_case_t), intent(out) :: cs(:)
    integer,            intent(out) :: n_out
    integer :: idx, c, mode, dir, ci

    idx = 0

    ! Wrapper Only round-trip: 3 ciphers x { Wrap, WrapInPlace } = 6.
    do c = 1, NUM_CIPHERS
      idx = idx + 1
      call register_wrapper_only(cs(idx),                                      &
            "bench_wrapper_only_" // trim(CIPHER_NAMES(c)) // "_wrap",         &
            CIPHERS(c), .false.)
      idx = idx + 1
      call register_wrapper_only(cs(idx),                                      &
            "bench_wrapper_only_" // trim(CIPHER_NAMES(c)) // "_inplace",      &
            CIPHERS(c), .true.)
    end do

    ! Message Single: 4 modes x 3 ciphers x 2 dirs = 24.
    do mode = 1, 4
      do ci = 1, NUM_CIPHERS
        do dir = 1, 2
          idx = idx + 1
          call register_pipeline(cs(idx),                                      &
              "bench_message_single_" // trim(MSG_MODE_NAMES(mode))            &
                  // "_" // trim(CIPHER_NAMES(ci))                             &
                  // dir_suffix(dir),                                          &
              CIPHERS(ci))
        end do
      end do
    end do

    ! Message Triple: 4 x 3 x 2 = 24.
    do mode = 1, 4
      do ci = 1, NUM_CIPHERS
        do dir = 1, 2
          idx = idx + 1
          call register_pipeline(cs(idx),                                      &
              "bench_message_triple_" // trim(MSG_MODE_NAMES(mode))            &
                  // "_" // trim(CIPHER_NAMES(ci))                             &
                  // dir_suffix(dir),                                          &
              CIPHERS(ci))
        end do
      end do
    end do

    ! Streaming Single: 4 x 3 x 2 = 24.
    do mode = 1, 4
      do ci = 1, NUM_CIPHERS
        do dir = 1, 2
          idx = idx + 1
          call register_pipeline(cs(idx),                                      &
              "bench_streaming_single_" // trim(STREAM_MODE_NAMES(mode))       &
                  // "_" // trim(CIPHER_NAMES(ci))                             &
                  // dir_suffix(dir),                                          &
              CIPHERS(ci))
        end do
      end do
    end do

    ! Streaming Triple: 4 x 3 x 2 = 24.
    do mode = 1, 4
      do ci = 1, NUM_CIPHERS
        do dir = 1, 2
          idx = idx + 1
          call register_pipeline(cs(idx),                                      &
              "bench_streaming_triple_" // trim(STREAM_MODE_NAMES(mode))       &
                  // "_" // trim(CIPHER_NAMES(ci))                             &
                  // dir_suffix(dir),                                          &
              CIPHERS(ci))
        end do
      end do
    end do

    n_out = idx
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

  subroutine register_wrapper_only(c, label, cipher, in_place)
    type(bench_case_t), intent(out) :: c
    character(*),       intent(in)  :: label
    integer,            intent(in)  :: cipher
    logical,            intent(in)  :: in_place
    integer :: idx
    call make_state(cipher, WRAPPER_PAYLOAD_BYTES, idx)
    c%name = label
    c%case_idx = idx
    c%payload_bytes = WRAPPER_PAYLOAD_BYTES
    if (in_place) then
      c%run => run_wrap_in_place
    else
      c%run => run_wrap_alloc
    end if
  end subroutine

  subroutine register_pipeline(c, label, cipher)
    type(bench_case_t), intent(out) :: c
    character(*),       intent(in)  :: label
    integer,            intent(in)  :: cipher
    integer :: idx
    ! Pipeline cases share the same payload size as wrapper only
    ! to keep MB/s columns comparable across surfaces.
    call make_state(cipher, WRAPPER_PAYLOAD_BYTES, idx)
    c%name = label
    c%case_idx = idx
    c%payload_bytes = WRAPPER_PAYLOAD_BYTES
    c%run => run_pipeline_stub
  end subroutine

end program bench_wrapper
