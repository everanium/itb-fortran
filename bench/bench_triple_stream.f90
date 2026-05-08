! bench_triple_stream.f90 -- Triple Ouroboros streaming benchmarks for
! the Fortran binding.
!
! Eight cases exercising the full Triple-Ouroboros streaming matrix at
! 64 MiB total payload / 16 MiB chunk size under areion512 + 1024-bit
! ITB key + hmac-blake3 MAC:
!
!     | Mode      | Op      | Variant   |
!     |-----------|---------|-----------|
!     | Easy      | Encrypt | AEAD IO   |
!     | Easy      | Decrypt | AEAD IO   |
!     | Easy      | Encrypt | UserLoop  |
!     | Easy      | Decrypt | UserLoop  |
!     | Low-Level | Encrypt | AEAD IO   |
!     | Low-Level | Decrypt | AEAD IO   |
!     | Low-Level | Encrypt | UserLoop  |
!     | Low-Level | Decrypt | UserLoop  |
!
! AEAD IO  -- Streaming AEAD over caller-supplied read_fn / write_fn
!             callbacks. Easy: itb_encryptor_stream_encrypt_auth /
!             _decrypt_auth. Low-Level: itb_stream_encrypt_auth /
!             itb_stream_decrypt_auth free subroutines over (noise,
!             data, start, mac).
!
! UserLoop -- Plain Streaming via caller-side per-chunk loop; framing
!             convention is a 4-byte big-endian ciphertext-length
!             prefix preceding each chunk's ciphertext bytes (matching
!             the canonical pattern in tmp/fortran.example.md). Easy
!             uses enc%encrypt / enc%decrypt; Low-Level uses itb_encrypt
!             / itb_decrypt free subroutines.
!
! Setup discipline: 64 MiB CSPRNG fill, encryptor / Seed / MAC
! construction, and (for Decrypt cases) the pre-encryption all run
! outside the timer. Each measured iteration walks fresh in-memory
! cursors over the prepared inputs / outputs and tears them down.
!
! Run with:
!
!   make bench
!   ./bench/bin/itb-bench-triple-stream
!
!   ITB_BENCH_FILTER=easy_encrypt_aead_io ./bench/bin/itb-bench-triple-stream

module bench_triple_stream_state
  use, intrinsic :: iso_fortran_env, only: int64, error_unit
  use, intrinsic :: iso_c_binding,   only: c_int8_t, c_size_t, c_ptr,        &
                                              c_null_ptr, c_loc
  use itb_kinds,     only: itb_byte_kind, itb_size_kind
  use itb_seed,      only: itb_seed_t
  use itb_mac,       only: itb_mac_t
  use itb_encryptor, only: itb_encryptor_t
  implicit none
  private

  public :: case_state_t
  public :: bench_states
  public :: bench_states_len
  public :: alloc_state
  public :: state_destroy_all
  public :: capture_byte_cptr
  public :: capture_int8_cptr

  ! Each per-case state stores the byte buffers as `allocatable`
  ! (owned by Fortran) plus the corresponding `c_ptr` aliases that
  ! are populated once at construction time. The c_ptr aliases are
  ! what feed into the mem_reader_t / mem_writer_t structs that the
  ! C-bind callbacks consume, sidestepping the gfortran requirement
  ! that c_loc(...) operands carry an explicit POINTER / TARGET
  ! attribute -- the c_loc(...) call lives at construction time
  ! against a local `target`-attributed allocatable, while the
  ! captured c_ptr is what every measured iteration uses.
  type :: case_state_t
    type(itb_encryptor_t)               :: enc
    ! Triple Ouroboros: 7 seed slots -- 1 noise, 3 data, 3 start.
    type(itb_seed_t)                    :: noise
    type(itb_seed_t)                    :: data1, data2, data3
    type(itb_seed_t)                    :: start1, start2, start3
    type(itb_mac_t)                     :: mac
    integer(itb_byte_kind), allocatable :: payload(:)
    integer(itb_byte_kind), allocatable :: transcript(:)
    integer(itb_size_kind)              :: transcript_len = 0_itb_size_kind
    integer(c_int8_t), allocatable      :: write_pool(:)
    integer(c_int8_t), allocatable      :: drain_pool(:)
    type(c_ptr)                         :: payload_cptr
    type(c_ptr)                         :: transcript_cptr
    type(c_ptr)                         :: write_pool_cptr
    type(c_ptr)                         :: drain_pool_cptr
  end type

  integer, parameter :: MAX_CASES = 16
  type(case_state_t), save :: bench_states(MAX_CASES)
  integer,            save :: bench_states_len = 0

contains

  function alloc_state() result(idx)
    integer :: idx
    if (bench_states_len >= MAX_CASES) then
      write (error_unit, "(A)") "bench_triple_stream: state registry exhausted"
      error stop 1
    end if
    bench_states_len = bench_states_len + 1
    idx = bench_states_len
  end function

  ! Captures the c_ptr of an allocatable byte buffer. The buffer is
  ! passed in as a `target, contiguous, intent(in)` dummy, which
  ! gives c_loc(...) the explicit attribute it requires under
  ! gfortran's strict F2018 interpretation. Caller stores the
  ! returned c_ptr in the case-state struct.
  subroutine capture_byte_cptr(buf, out_ptr)
    integer(itb_byte_kind), target, contiguous, intent(in)  :: buf(:)
    type(c_ptr),                                intent(out) :: out_ptr
    if (size(buf) == 0) then
      out_ptr = c_null_ptr
    else
      out_ptr = c_loc(buf)
    end if
  end subroutine

  subroutine capture_int8_cptr(buf, out_ptr)
    integer(c_int8_t), target, contiguous, intent(in)  :: buf(:)
    type(c_ptr),                           intent(out) :: out_ptr
    if (size(buf) == 0) then
      out_ptr = c_null_ptr
    else
      out_ptr = c_loc(buf)
    end if
  end subroutine

  subroutine state_destroy_all()
    integer :: i
    do i = 1, bench_states_len
      call bench_states(i)%enc%destroy()
      call bench_states(i)%noise%destroy()
      call bench_states(i)%data1%destroy()
      call bench_states(i)%data2%destroy()
      call bench_states(i)%data3%destroy()
      call bench_states(i)%start1%destroy()
      call bench_states(i)%start2%destroy()
      call bench_states(i)%start3%destroy()
      call bench_states(i)%mac%destroy()
      if (allocated(bench_states(i)%payload))    deallocate (bench_states(i)%payload)
      if (allocated(bench_states(i)%transcript)) deallocate (bench_states(i)%transcript)
      if (allocated(bench_states(i)%write_pool)) deallocate (bench_states(i)%write_pool)
      if (allocated(bench_states(i)%drain_pool)) deallocate (bench_states(i)%drain_pool)
      bench_states(i)%payload_cptr    = c_null_ptr
      bench_states(i)%transcript_cptr = c_null_ptr
      bench_states(i)%write_pool_cptr = c_null_ptr
      bench_states(i)%drain_pool_cptr = c_null_ptr
    end do
    bench_states_len = 0
  end subroutine

end module bench_triple_stream_state


! In-memory reader / writer callback module. Pre-allocated writer
! capacity covers the worst-case AEAD output (~1.04x payload + 32
! bytes prefix + 1 byte/chunk flag) by a wide margin -- the writer
! never grows mid-iteration. Mid-iteration overflow indicates a
! sizing bug and the writer callback returns a non-zero status to
! abort the stream.
module bench_triple_stream_io
  use, intrinsic :: iso_c_binding
  use itb_kinds,  only: itb_byte_kind, itb_size_kind
  implicit none
  private

  public :: mem_reader_t, mem_writer_t
  public :: mem_read_fn, mem_write_fn

  type, bind(C) :: mem_reader_t
    integer(c_size_t) :: total = 0_c_size_t
    integer(c_size_t) :: pos   = 0_c_size_t
    type(c_ptr)       :: data  = c_null_ptr
  end type

  type, bind(C) :: mem_writer_t
    integer(c_size_t) :: cap = 0_c_size_t
    integer(c_size_t) :: len = 0_c_size_t
    type(c_ptr)       :: data = c_null_ptr
  end type

contains

  function mem_read_fn(user_ctx, buf, cap, out_n) bind(C) result(rc)
    type(c_ptr),       value :: user_ctx
    type(c_ptr),       value :: buf
    integer(c_size_t), value :: cap
    integer(c_size_t)        :: out_n
    integer(c_int)           :: rc
    type(mem_reader_t), pointer :: r
    integer(c_int8_t),  pointer :: src_arr(:), dst_arr(:)
    integer(c_size_t)           :: avail, take, i

    call c_f_pointer(user_ctx, r)
    avail = r%total - r%pos
    take  = min(cap, avail)
    if (take > 0_c_size_t) then
      call c_f_pointer(r%data, src_arr, [r%total])
      call c_f_pointer(buf,    dst_arr, [take])
      do i = 1_c_size_t, take
        dst_arr(i) = src_arr(r%pos + i)
      end do
      r%pos = r%pos + take
    end if
    out_n = take
    rc = 0_c_int
  end function

  function mem_write_fn(user_ctx, buf, n) bind(C) result(rc)
    type(c_ptr),       value :: user_ctx
    type(c_ptr),       value :: buf
    integer(c_size_t), value :: n
    integer(c_int)           :: rc
    type(mem_writer_t), pointer :: w
    integer(c_int8_t),  pointer :: src_arr(:), dst_arr(:)
    integer(c_size_t)           :: i

    call c_f_pointer(user_ctx, w)
    if (n == 0_c_size_t) then
      rc = 0_c_int
      return
    end if
    if (w%len + n > w%cap) then
      rc = 1_c_int
      return
    end if
    call c_f_pointer(buf,    src_arr, [n])
    call c_f_pointer(w%data, dst_arr, [w%cap])
    do i = 1_c_size_t, n
      dst_arr(w%len + i) = src_arr(i)
    end do
    w%len = w%len + n
    rc = 0_c_int
  end function

end module bench_triple_stream_io


program bench_triple_stream
  use, intrinsic :: iso_fortran_env, only: int64, output_unit
  use, intrinsic :: iso_c_binding
  use itb_kinds,     only: itb_byte_kind, itb_size_kind
  use itb_library,   only: itb_set_max_workers, itb_set_nonce_bits
  use itb_seed,      only: new_itb_seed
  use itb_mac,       only: new_itb_mac
  use itb_encryptor, only: new_itb_encryptor
  use itb_cipher,    only: itb_encrypt_triple, itb_decrypt_triple
  use itb_streams,   only: itb_stream_encrypt_auth_triple,                   &
                           itb_stream_decrypt_auth_triple,                    &
                           itb_encryptor_stream_encrypt_auth,                 &
                           itb_encryptor_stream_decrypt_auth,                 &
                           itb_stream_read_fn, itb_stream_write_fn
  use itb_errors,    only: STATUS_OK
  use bench_common,  only: env_lock_seed, env_nonce_bits, random_bytes,      &
                           run_all, bench_case_t
  use bench_triple_stream_state
  use bench_triple_stream_io
  implicit none

  character(*),         parameter :: STREAM_PRIMITIVE = "areion512"
  integer,              parameter :: STREAM_KEY_BITS  = 1024
  character(*),         parameter :: STREAM_MAC_NAME  = "hmac-blake3"
  integer(c_size_t),    parameter :: STREAM_TOTAL_BYTES = int(64_c_size_t * 1024_c_size_t * 1024_c_size_t, c_size_t)
  integer(c_size_t),    parameter :: STREAM_CHUNK_BYTES = int(16_c_size_t * 1024_c_size_t * 1024_c_size_t, c_size_t)

  ! Fixed 32-byte MAC key -- value content is immaterial for
  ! throughput measurement; the MAC executes in O(MAC-key-length) per
  ! absorb regardless of byte distribution. Values from the
  ! cross-binding canonical key 0x11 0x22 ... 0x01.
  integer, parameter :: STREAM_MAC_KEY_INTS(32) = [                         &
      int(z'11'), int(z'22'), int(z'33'), int(z'44'),                        &
      int(z'55'), int(z'66'), int(z'77'), int(z'88'),                        &
      int(z'99'), int(z'AA'), int(z'BB'), int(z'CC'),                        &
      int(z'DD'), int(z'EE'), int(z'FF'), int(z'00'),                        &
      int(z'10'), int(z'20'), int(z'30'), int(z'40'),                        &
      int(z'50'), int(z'60'), int(z'70'), int(z'80'),                        &
      int(z'90'), int(z'A0'), int(z'B0'), int(z'C0'),                        &
      int(z'D0'), int(z'E0'), int(z'F0'), int(z'01')]

  integer, parameter :: TOTAL_CASES = 8

  type(bench_case_t) :: cases(TOTAL_CASES)
  integer            :: nonce_bits, n

  nonce_bits = env_nonce_bits(128)
  call itb_set_max_workers(0)
  call itb_set_nonce_bits(nonce_bits)

  write (output_unit, "(A,I0,A,I0,A,A,A,I0,A,A,A,I0,A,A,A)") &
      "# triple_stream payload_bytes=", STREAM_TOTAL_BYTES,             &
      " chunk_bytes=",   STREAM_CHUNK_BYTES,                             &
      " primitive=",     STREAM_PRIMITIVE,                               &
      " key_bits=",      STREAM_KEY_BITS,                                &
      " mac=",           STREAM_MAC_NAME,                                &
      " nonce_bits=",    nonce_bits,                                     &
      " lockseed=",      merge("on ", "off", env_lock_seed()),           &
      " workers=auto"
  flush(output_unit)

  call build_cases(cases, n)
  call run_all(cases, n)
  call state_destroy_all()

contains

  ! ---- Construction helpers --------------------------------------------

  subroutine build_stream_encryptor(idx)
    integer, intent(in) :: idx
    ! Mode 3 = Triple Ouroboros (7 seed slots).
    call new_itb_encryptor(bench_states(idx)%enc, STREAM_PRIMITIVE,         &
                            STREAM_KEY_BITS, STREAM_MAC_NAME, 3)
    if (env_lock_seed()) call bench_states(idx)%enc%set_lock_seed(1)
  end subroutine

  subroutine build_stream_seeds(idx)
    integer, intent(in) :: idx
    call new_itb_seed(bench_states(idx)%noise,  STREAM_PRIMITIVE, STREAM_KEY_BITS)
    call new_itb_seed(bench_states(idx)%data1,  STREAM_PRIMITIVE, STREAM_KEY_BITS)
    call new_itb_seed(bench_states(idx)%data2,  STREAM_PRIMITIVE, STREAM_KEY_BITS)
    call new_itb_seed(bench_states(idx)%data3,  STREAM_PRIMITIVE, STREAM_KEY_BITS)
    call new_itb_seed(bench_states(idx)%start1, STREAM_PRIMITIVE, STREAM_KEY_BITS)
    call new_itb_seed(bench_states(idx)%start2, STREAM_PRIMITIVE, STREAM_KEY_BITS)
    call new_itb_seed(bench_states(idx)%start3, STREAM_PRIMITIVE, STREAM_KEY_BITS)
  end subroutine

  subroutine build_stream_mac(idx)
    integer, intent(in) :: idx
    integer(itb_byte_kind), target :: key_view(32)
    integer :: i, v
    do i = 1, 32
      v = STREAM_MAC_KEY_INTS(i)
      ! Wrap into signed int8 range without overflow at the int->
      ! itb_byte_kind conversion: values 128..255 become -128..-1.
      if (v >= 128) v = v - 256
      key_view(i) = int(v, itb_byte_kind)
    end do
    call new_itb_mac(bench_states(idx)%mac, STREAM_MAC_NAME, key_view)
  end subroutine

  subroutine fill_payload(idx)
    integer, intent(in) :: idx
    integer(int64), allocatable :: scratch(:)
    integer(int64) :: i
    type(c_ptr) :: tmp_cptr
    allocate (scratch(STREAM_TOTAL_BYTES))
    call random_bytes(scratch, int(STREAM_TOTAL_BYTES, int64))
    allocate (bench_states(idx)%payload(STREAM_TOTAL_BYTES))
    do i = 1, int(STREAM_TOTAL_BYTES, int64)
      bench_states(idx)%payload(i) = int(scratch(i), itb_byte_kind)
    end do
    deallocate (scratch)
    call capture_byte_cptr(bench_states(idx)%payload, tmp_cptr)
    bench_states(idx)%payload_cptr = tmp_cptr
  end subroutine

  ! ---- 4-byte BE length-prefix UserLoop framing ------------------------

  ! Writes a 4-byte big-endian length-prefix header followed by
  ! `ct_bytes` into the pre-allocated `transcript` at offset
  ! `transcript_len`, advancing `transcript_len` by the header + payload
  ! length. The caller is responsible for pre-allocating `transcript`
  ! to a capacity that covers every chunk of the stream (1.125x payload
  ! suffices for the bench's worst case, mirroring the C harness's
  ! `mem_writer_init` sizing). Mid-stream growth is intentionally
  ! disallowed: per-chunk reallocate-and-copy was the dominant cost on
  ! the User-Loop encrypt path before this discipline. Array-section
  ! assignment lowers to a single `memcpy` under gfortran instead of an
  ! element-wise byte copy.
  subroutine frame_chunk(transcript, transcript_len, ct_bytes)
    integer(itb_byte_kind), allocatable, intent(inout) :: transcript(:)
    integer(itb_size_kind),              intent(inout) :: transcript_len
    integer(itb_byte_kind),              intent(in)    :: ct_bytes(:)
    integer(itb_size_kind) :: ct_len, new_total
    integer(itb_byte_kind) :: hdr(4)

    ct_len = int(size(ct_bytes), itb_size_kind)
    hdr(1) = int(iand(ishft(ct_len, -24), 255_itb_size_kind), itb_byte_kind)
    hdr(2) = int(iand(ishft(ct_len, -16), 255_itb_size_kind), itb_byte_kind)
    hdr(3) = int(iand(ishft(ct_len, -8),  255_itb_size_kind), itb_byte_kind)
    hdr(4) = int(iand(ct_len,             255_itb_size_kind), itb_byte_kind)

    new_total = transcript_len + 4_itb_size_kind + ct_len
    if (.not. allocated(transcript)) then
      error stop "frame_chunk: transcript_buf not pre-allocated -- caller must size to STREAM_TOTAL_BYTES + STREAM_TOTAL_BYTES/8"
    end if
    if (int(size(transcript), itb_size_kind) < new_total) then
      error stop "frame_chunk: transcript_buf undersized -- increase prealloc"
    end if
    transcript(transcript_len + 1_itb_size_kind : transcript_len + 4_itb_size_kind) = hdr(1:4)
    transcript_len = transcript_len + 4_itb_size_kind
    transcript(transcript_len + 1_itb_size_kind : transcript_len + ct_len) = ct_bytes(1:ct_len)
    transcript_len = transcript_len + ct_len
  end subroutine

  ! Reads a 4-byte big-endian length prefix from `transcript` at
  ! offset `off`. Caller has already verified at least 4 bytes are
  ! available.
  pure function unframe_len(transcript, off) result(n)
    integer(itb_byte_kind), intent(in) :: transcript(:)
    integer(itb_size_kind), intent(in) :: off
    integer(itb_size_kind)             :: n
    integer(itb_size_kind) :: b0, b1, b2, b3
    b0 = iand(int(transcript(off + 1), itb_size_kind), 255_itb_size_kind)
    b1 = iand(int(transcript(off + 2), itb_size_kind), 255_itb_size_kind)
    b2 = iand(int(transcript(off + 3), itb_size_kind), 255_itb_size_kind)
    b3 = iand(int(transcript(off + 4), itb_size_kind), 255_itb_size_kind)
    n = ior(ior(ishft(b0, 24), ishft(b1, 16)), ior(ishft(b2, 8), b3))
  end function

  ! ---- Per-iter callables --------------------------------------------
  !
  ! Each per-iter callable runs the chosen cipher path against the
  ! pre-built `bench_states(case_idx)` payload / transcript and tears
  ! down its in-memory cursors after each iteration.

  subroutine run_easy_encrypt_aead_io(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    type(mem_reader_t), target :: r
    type(mem_writer_t), target :: w
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer :: status
    rfn => mem_read_fn
    wfn => mem_write_fn
    do i = 1_int64, iters
      r%total = STREAM_TOTAL_BYTES
      r%pos   = 0_c_size_t
      r%data  = bench_states(case_idx)%payload_cptr
      w%cap   = int(size(bench_states(case_idx)%write_pool), c_size_t)
      w%len   = 0_c_size_t
      w%data  = bench_states(case_idx)%write_pool_cptr
      call itb_encryptor_stream_encrypt_auth(bench_states(case_idx)%enc,    &
            rfn, c_loc(r), wfn, c_loc(w),                                   &
            int(STREAM_CHUNK_BYTES, itb_size_kind), status)
      if (status /= STATUS_OK) error stop "easy stream_encrypt_auth failed"
    end do
  end subroutine

  subroutine run_easy_decrypt_aead_io(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    type(mem_reader_t), target :: r
    type(mem_writer_t), target :: w
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer :: status
    rfn => mem_read_fn
    wfn => mem_write_fn
    do i = 1_int64, iters
      r%total = int(bench_states(case_idx)%transcript_len, c_size_t)
      r%pos   = 0_c_size_t
      r%data  = bench_states(case_idx)%transcript_cptr
      w%cap   = int(size(bench_states(case_idx)%drain_pool), c_size_t)
      w%len   = 0_c_size_t
      w%data  = bench_states(case_idx)%drain_pool_cptr
      call itb_encryptor_stream_decrypt_auth(bench_states(case_idx)%enc,    &
            rfn, c_loc(r), wfn, c_loc(w),                                   &
            int(STREAM_CHUNK_BYTES, itb_size_kind), status)
      if (status /= STATUS_OK) error stop "easy stream_decrypt_auth failed"
    end do
  end subroutine

  subroutine run_easy_encrypt_userloop(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_size_kind) :: off, end_off, chunk
    integer(itb_byte_kind), allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: transcript_buf(:)
    integer(itb_size_kind) :: transcript_len
    integer(itb_size_kind) :: cap
    ! Pre-allocate the transcript buffer to 1.5x payload + 32 KiB,
    ! matching alloc_write_pool's AEAD-side sizing. The plain
    ! per-chunk container (length-prefix + ITB ciphertext envelope
    ! per chunk) can exceed a 1.125x bulk-rate cap on smaller chunks,
    ! so the bench mirrors the AEAD sizing rather than the C harness's
    ! 1.125x mem_writer_init cap. frame_chunk writes in-place via
    ! array-section assignment instead of growing per-chunk, so the
    ! User-Loop encrypt path measures cipher work rather than O(N^2)
    ! reallocate-and-copy.
    cap = int(STREAM_TOTAL_BYTES, itb_size_kind)                              &
        + ishft(int(STREAM_TOTAL_BYTES, itb_size_kind), -1)                  &
        + 32_itb_size_kind * 1024_itb_size_kind
    do i = 1_int64, iters
      allocate (transcript_buf(cap))
      transcript_len = 0_itb_size_kind
      off = 0_itb_size_kind
      do while (off < int(STREAM_TOTAL_BYTES, itb_size_kind))
        chunk = int(STREAM_CHUNK_BYTES, itb_size_kind)
        end_off = off + chunk
        if (end_off > int(STREAM_TOTAL_BYTES, itb_size_kind))             &
            end_off = int(STREAM_TOTAL_BYTES, itb_size_kind)
        ct = bench_states(case_idx)%enc%encrypt(                            &
              bench_states(case_idx)%payload(int(off) + 1:int(end_off)))
        call frame_chunk(transcript_buf, transcript_len, ct)
        deallocate (ct)
        off = end_off
      end do
      deallocate (transcript_buf)
    end do
  end subroutine

  subroutine run_easy_decrypt_userloop(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_size_kind) :: off, ct_len
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable :: pt_accum(:)
    integer(itb_size_kind) :: pt_len, j, total_len
    do i = 1_int64, iters
      total_len = bench_states(case_idx)%transcript_len
      allocate (pt_accum(STREAM_TOTAL_BYTES))
      pt_len = 0_itb_size_kind
      off = 0_itb_size_kind
      do while (off + 4_itb_size_kind <= total_len)
        ct_len = unframe_len(bench_states(case_idx)%transcript, off)
        off = off + 4_itb_size_kind
        if (off + ct_len > total_len) error stop "easy decrypt userloop: truncated transcript"
        pt = bench_states(case_idx)%enc%decrypt(                            &
              bench_states(case_idx)%transcript(int(off) + 1:int(off + ct_len)))
        do j = 1_itb_size_kind, int(size(pt), itb_size_kind)
          pt_accum(pt_len + j) = pt(j)
        end do
        pt_len = pt_len + int(size(pt), itb_size_kind)
        deallocate (pt)
        off = off + ct_len
      end do
      deallocate (pt_accum)
    end do
  end subroutine

  subroutine run_lowlevel_encrypt_aead_io(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    type(mem_reader_t), target :: r
    type(mem_writer_t), target :: w
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer :: status
    rfn => mem_read_fn
    wfn => mem_write_fn
    do i = 1_int64, iters
      r%total = STREAM_TOTAL_BYTES
      r%pos   = 0_c_size_t
      r%data  = bench_states(case_idx)%payload_cptr
      w%cap   = int(size(bench_states(case_idx)%write_pool), c_size_t)
      w%len   = 0_c_size_t
      w%data  = bench_states(case_idx)%write_pool_cptr
      call itb_stream_encrypt_auth_triple(bench_states(case_idx)%noise,     &
            bench_states(case_idx)%data1, bench_states(case_idx)%data2,      &
            bench_states(case_idx)%data3,                                    &
            bench_states(case_idx)%start1, bench_states(case_idx)%start2,    &
            bench_states(case_idx)%start3,                                   &
            bench_states(case_idx)%mac,                                       &
            rfn, c_loc(r), wfn, c_loc(w),                                    &
            int(STREAM_CHUNK_BYTES, itb_size_kind), status)
      if (status /= STATUS_OK) error stop "low-level stream_encrypt_auth_triple failed"
    end do
  end subroutine

  subroutine run_lowlevel_decrypt_aead_io(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    type(mem_reader_t), target :: r
    type(mem_writer_t), target :: w
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer :: status
    rfn => mem_read_fn
    wfn => mem_write_fn
    do i = 1_int64, iters
      r%total = int(bench_states(case_idx)%transcript_len, c_size_t)
      r%pos   = 0_c_size_t
      r%data  = bench_states(case_idx)%transcript_cptr
      w%cap   = int(size(bench_states(case_idx)%drain_pool), c_size_t)
      w%len   = 0_c_size_t
      w%data  = bench_states(case_idx)%drain_pool_cptr
      call itb_stream_decrypt_auth_triple(bench_states(case_idx)%noise,     &
            bench_states(case_idx)%data1, bench_states(case_idx)%data2,      &
            bench_states(case_idx)%data3,                                    &
            bench_states(case_idx)%start1, bench_states(case_idx)%start2,    &
            bench_states(case_idx)%start3,                                   &
            bench_states(case_idx)%mac,                                       &
            rfn, c_loc(r), wfn, c_loc(w),                                    &
            int(STREAM_CHUNK_BYTES, itb_size_kind), status)
      if (status /= STATUS_OK) error stop "low-level stream_decrypt_auth_triple failed"
    end do
  end subroutine

  subroutine run_lowlevel_encrypt_userloop(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_size_kind) :: off, end_off, chunk
    integer(itb_byte_kind), allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: transcript_buf(:)
    integer(itb_size_kind) :: transcript_len
    integer(itb_size_kind) :: cap
    ! Pre-allocate the transcript buffer to 1.5x payload + 32 KiB.
    ! See run_easy_encrypt_userloop for the rationale.
    cap = int(STREAM_TOTAL_BYTES, itb_size_kind)                              &
        + ishft(int(STREAM_TOTAL_BYTES, itb_size_kind), -1)                  &
        + 32_itb_size_kind * 1024_itb_size_kind
    do i = 1_int64, iters
      allocate (transcript_buf(cap))
      transcript_len = 0_itb_size_kind
      off = 0_itb_size_kind
      do while (off < int(STREAM_TOTAL_BYTES, itb_size_kind))
        chunk = int(STREAM_CHUNK_BYTES, itb_size_kind)
        end_off = off + chunk
        if (end_off > int(STREAM_TOTAL_BYTES, itb_size_kind))              &
            end_off = int(STREAM_TOTAL_BYTES, itb_size_kind)
        ct = itb_encrypt_triple(bench_states(case_idx)%noise,                &
                          bench_states(case_idx)%data1,                       &
                          bench_states(case_idx)%data2,                       &
                          bench_states(case_idx)%data3,                       &
                          bench_states(case_idx)%start1,                      &
                          bench_states(case_idx)%start2,                      &
                          bench_states(case_idx)%start3,                      &
                          bench_states(case_idx)%payload(int(off) + 1:int(end_off)))
        call frame_chunk(transcript_buf, transcript_len, ct)
        deallocate (ct)
        off = end_off
      end do
      deallocate (transcript_buf)
    end do
  end subroutine

  subroutine run_lowlevel_decrypt_userloop(case_idx, iters)
    integer,        intent(in) :: case_idx
    integer(int64), intent(in) :: iters
    integer(int64) :: i
    integer(itb_size_kind) :: off, ct_len
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable :: pt_accum(:)
    integer(itb_size_kind) :: pt_len, j, total_len
    do i = 1_int64, iters
      total_len = bench_states(case_idx)%transcript_len
      allocate (pt_accum(STREAM_TOTAL_BYTES))
      pt_len = 0_itb_size_kind
      off = 0_itb_size_kind
      do while (off + 4_itb_size_kind <= total_len)
        ct_len = unframe_len(bench_states(case_idx)%transcript, off)
        off = off + 4_itb_size_kind
        if (off + ct_len > total_len) error stop "low-level decrypt userloop: truncated transcript"
        pt = itb_decrypt_triple(bench_states(case_idx)%noise,                &
                          bench_states(case_idx)%data1,                       &
                          bench_states(case_idx)%data2,                       &
                          bench_states(case_idx)%data3,                       &
                          bench_states(case_idx)%start1,                      &
                          bench_states(case_idx)%start2,                      &
                          bench_states(case_idx)%start3,                      &
                          bench_states(case_idx)%transcript(int(off) + 1:int(off + ct_len)))
        do j = 1_itb_size_kind, int(size(pt), itb_size_kind)
          pt_accum(pt_len + j) = pt(j)
        end do
        pt_len = pt_len + int(size(pt), itb_size_kind)
        deallocate (pt)
        off = off + ct_len
      end do
      deallocate (pt_accum)
    end do
  end subroutine

  ! ---- Pre-encrypt transcript builders --------------------------------

  subroutine prebuild_easy_aead_transcript(idx)
    integer, intent(in) :: idx
    type(mem_reader_t), target :: r
    type(mem_writer_t), target :: w
    integer(c_int8_t), allocatable, target :: pool(:)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer :: status
    integer(c_size_t) :: i
    integer(c_size_t) :: cap
    ! 1.5x payload + 32 KiB headroom -- worst-case AEAD chunk
    ! expansion under barrier-fill > 1 plus the per-chunk MAC tag,
    ! flag byte, and CSPRNG fill can lift the per-chunk output well
    ! past the 1.125x bulk-rate ratio. Sizing the writer pool
    ! generously here is a one-time setup cost; the actual
    ! per-iteration measured work is dominated by the cipher
    ! pipeline, not the pool's initial allocation.
    cap = STREAM_TOTAL_BYTES + ishft(STREAM_TOTAL_BYTES, -1) + 32_c_size_t * 1024_c_size_t
    rfn => mem_read_fn
    wfn => mem_write_fn
    allocate (pool(cap))
    r%total = STREAM_TOTAL_BYTES
    r%pos   = 0_c_size_t
    r%data  = bench_states(idx)%payload_cptr
    w%cap   = cap
    w%len   = 0_c_size_t
    w%data  = c_loc(pool)
    call itb_encryptor_stream_encrypt_auth(bench_states(idx)%enc,           &
          rfn, c_loc(r), wfn, c_loc(w),                                     &
          int(STREAM_CHUNK_BYTES, itb_size_kind), status)
    if (status /= STATUS_OK) error stop "prebuild easy AEAD transcript failed"
    allocate (bench_states(idx)%transcript(int(w%len, itb_size_kind)))
    do i = 1_c_size_t, w%len
      bench_states(idx)%transcript(int(i, itb_size_kind)) = int(pool(i), itb_byte_kind)
    end do
    bench_states(idx)%transcript_len = int(w%len, itb_size_kind)
    call capture_byte_cptr(bench_states(idx)%transcript, bench_states(idx)%transcript_cptr)
    deallocate (pool)
  end subroutine

  subroutine prebuild_lowlevel_aead_transcript(idx)
    integer, intent(in) :: idx
    type(mem_reader_t), target :: r
    type(mem_writer_t), target :: w
    integer(c_int8_t), allocatable, target :: pool(:)
    procedure(itb_stream_read_fn),  pointer :: rfn => null()
    procedure(itb_stream_write_fn), pointer :: wfn => null()
    integer :: status
    integer(c_size_t) :: i
    integer(c_size_t) :: cap
    ! 1.5x payload + 32 KiB headroom -- worst-case AEAD chunk
    ! expansion under barrier-fill > 1 plus the per-chunk MAC tag,
    ! flag byte, and CSPRNG fill can lift the per-chunk output well
    ! past the 1.125x bulk-rate ratio. Sizing the writer pool
    ! generously here is a one-time setup cost; the actual
    ! per-iteration measured work is dominated by the cipher
    ! pipeline, not the pool's initial allocation.
    cap = STREAM_TOTAL_BYTES + ishft(STREAM_TOTAL_BYTES, -1) + 32_c_size_t * 1024_c_size_t
    rfn => mem_read_fn
    wfn => mem_write_fn
    allocate (pool(cap))
    r%total = STREAM_TOTAL_BYTES
    r%pos   = 0_c_size_t
    r%data  = bench_states(idx)%payload_cptr
    w%cap   = cap
    w%len   = 0_c_size_t
    w%data  = c_loc(pool)
    call itb_stream_encrypt_auth_triple(bench_states(idx)%noise,            &
          bench_states(idx)%data1, bench_states(idx)%data2,                  &
          bench_states(idx)%data3,                                            &
          bench_states(idx)%start1, bench_states(idx)%start2,                &
          bench_states(idx)%start3,                                            &
          bench_states(idx)%mac,                                              &
          rfn, c_loc(r), wfn, c_loc(w),                                      &
          int(STREAM_CHUNK_BYTES, itb_size_kind), status)
    if (status /= STATUS_OK) error stop "prebuild low-level AEAD transcript failed"
    allocate (bench_states(idx)%transcript(int(w%len, itb_size_kind)))
    do i = 1_c_size_t, w%len
      bench_states(idx)%transcript(int(i, itb_size_kind)) = int(pool(i), itb_byte_kind)
    end do
    bench_states(idx)%transcript_len = int(w%len, itb_size_kind)
    call capture_byte_cptr(bench_states(idx)%transcript, bench_states(idx)%transcript_cptr)
    deallocate (pool)
  end subroutine

  subroutine prebuild_easy_userloop_transcript(idx)
    integer, intent(in) :: idx
    integer(itb_size_kind) :: off, end_off
    integer(itb_byte_kind), allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: transcript_buf(:)
    integer(itb_size_kind) :: transcript_len
    integer(itb_size_kind) :: cap
    cap = int(STREAM_TOTAL_BYTES, itb_size_kind)                              &
        + ishft(int(STREAM_TOTAL_BYTES, itb_size_kind), -1)                  &
        + 32_itb_size_kind * 1024_itb_size_kind
    allocate (transcript_buf(cap))
    transcript_len = 0_itb_size_kind
    off = 0_itb_size_kind
    do while (off < int(STREAM_TOTAL_BYTES, itb_size_kind))
      end_off = off + int(STREAM_CHUNK_BYTES, itb_size_kind)
      if (end_off > int(STREAM_TOTAL_BYTES, itb_size_kind))                &
          end_off = int(STREAM_TOTAL_BYTES, itb_size_kind)
      ct = bench_states(idx)%enc%encrypt(                                    &
            bench_states(idx)%payload(int(off) + 1:int(end_off)))
      call frame_chunk(transcript_buf, transcript_len, ct)
      deallocate (ct)
      off = end_off
    end do
    call move_alloc(transcript_buf, bench_states(idx)%transcript)
    bench_states(idx)%transcript_len = transcript_len
    call capture_byte_cptr(bench_states(idx)%transcript, bench_states(idx)%transcript_cptr)
  end subroutine

  subroutine prebuild_lowlevel_userloop_transcript(idx)
    integer, intent(in) :: idx
    integer(itb_size_kind) :: off, end_off
    integer(itb_byte_kind), allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: transcript_buf(:)
    integer(itb_size_kind) :: transcript_len
    integer(itb_size_kind) :: cap
    cap = int(STREAM_TOTAL_BYTES, itb_size_kind)                              &
        + ishft(int(STREAM_TOTAL_BYTES, itb_size_kind), -1)                  &
        + 32_itb_size_kind * 1024_itb_size_kind
    allocate (transcript_buf(cap))
    transcript_len = 0_itb_size_kind
    off = 0_itb_size_kind
    do while (off < int(STREAM_TOTAL_BYTES, itb_size_kind))
      end_off = off + int(STREAM_CHUNK_BYTES, itb_size_kind)
      if (end_off > int(STREAM_TOTAL_BYTES, itb_size_kind))                &
          end_off = int(STREAM_TOTAL_BYTES, itb_size_kind)
      ct = itb_encrypt_triple(bench_states(idx)%noise,                       &
                        bench_states(idx)%data1,                              &
                        bench_states(idx)%data2,                              &
                        bench_states(idx)%data3,                              &
                        bench_states(idx)%start1,                             &
                        bench_states(idx)%start2,                             &
                        bench_states(idx)%start3,                             &
                        bench_states(idx)%payload(int(off) + 1:int(end_off)))
      call frame_chunk(transcript_buf, transcript_len, ct)
      deallocate (ct)
      off = end_off
    end do
    call move_alloc(transcript_buf, bench_states(idx)%transcript)
    bench_states(idx)%transcript_len = transcript_len
    call capture_byte_cptr(bench_states(idx)%transcript, bench_states(idx)%transcript_cptr)
  end subroutine

  ! ---- Case constructors ----------------------------------------------

  ! Allocates the writer pool sized for AEAD encrypt output (~1.04x
  ! payload + per-stream prefix; the 1.125x cap covers comfortably).
  ! Used by every encrypt-side AEAD IO case.
  subroutine alloc_write_pool(idx)
    integer, intent(in) :: idx
    integer(c_size_t) :: cap
    ! 1.5x payload + 32 KiB headroom -- worst-case AEAD chunk
    ! expansion under barrier-fill > 1 plus the per-chunk MAC tag,
    ! flag byte, and CSPRNG fill can lift the per-chunk output well
    ! past the 1.125x bulk-rate ratio. Sizing the writer pool
    ! generously here is a one-time setup cost; the actual
    ! per-iteration measured work is dominated by the cipher
    ! pipeline, not the pool's initial allocation.
    cap = STREAM_TOTAL_BYTES + ishft(STREAM_TOTAL_BYTES, -1) + 32_c_size_t * 1024_c_size_t
    allocate (bench_states(idx)%write_pool(cap))
    call capture_int8_cptr(bench_states(idx)%write_pool, bench_states(idx)%write_pool_cptr)
  end subroutine

  ! Allocates the drain pool sized for plaintext recovery on decrypt.
  ! Plaintext length equals payload length exactly; round to total
  ! bytes for safety.
  subroutine alloc_drain_pool(idx)
    integer, intent(in) :: idx
    allocate (bench_states(idx)%drain_pool(STREAM_TOTAL_BYTES))
    call capture_int8_cptr(bench_states(idx)%drain_pool, bench_states(idx)%drain_pool_cptr)
  end subroutine

  subroutine make_easy_encrypt_aead_io(name_in, c)
    character(*),       intent(in)  :: name_in
    type(bench_case_t), intent(out) :: c
    integer :: idx
    idx = alloc_state()
    call build_stream_encryptor(idx)
    call fill_payload(idx)
    call alloc_write_pool(idx)
    c%name = name_in
    c%case_idx = idx
    c%payload_bytes = int(STREAM_TOTAL_BYTES, int64)
    c%run => run_easy_encrypt_aead_io
  end subroutine

  subroutine make_easy_decrypt_aead_io(name_in, c)
    character(*),       intent(in)  :: name_in
    type(bench_case_t), intent(out) :: c
    integer :: idx
    idx = alloc_state()
    call build_stream_encryptor(idx)
    call fill_payload(idx)
    call prebuild_easy_aead_transcript(idx)
    call alloc_drain_pool(idx)
    c%name = name_in
    c%case_idx = idx
    c%payload_bytes = int(STREAM_TOTAL_BYTES, int64)
    c%run => run_easy_decrypt_aead_io
  end subroutine

  subroutine make_easy_encrypt_userloop(name_in, c)
    character(*),       intent(in)  :: name_in
    type(bench_case_t), intent(out) :: c
    integer :: idx
    idx = alloc_state()
    call build_stream_encryptor(idx)
    call fill_payload(idx)
    c%name = name_in
    c%case_idx = idx
    c%payload_bytes = int(STREAM_TOTAL_BYTES, int64)
    c%run => run_easy_encrypt_userloop
  end subroutine

  subroutine make_easy_decrypt_userloop(name_in, c)
    character(*),       intent(in)  :: name_in
    type(bench_case_t), intent(out) :: c
    integer :: idx
    idx = alloc_state()
    call build_stream_encryptor(idx)
    call fill_payload(idx)
    call prebuild_easy_userloop_transcript(idx)
    c%name = name_in
    c%case_idx = idx
    c%payload_bytes = int(STREAM_TOTAL_BYTES, int64)
    c%run => run_easy_decrypt_userloop
  end subroutine

  subroutine make_lowlevel_encrypt_aead_io(name_in, c)
    character(*),       intent(in)  :: name_in
    type(bench_case_t), intent(out) :: c
    integer :: idx
    idx = alloc_state()
    call build_stream_seeds(idx)
    call build_stream_mac(idx)
    call fill_payload(idx)
    call alloc_write_pool(idx)
    c%name = name_in
    c%case_idx = idx
    c%payload_bytes = int(STREAM_TOTAL_BYTES, int64)
    c%run => run_lowlevel_encrypt_aead_io
  end subroutine

  subroutine make_lowlevel_decrypt_aead_io(name_in, c)
    character(*),       intent(in)  :: name_in
    type(bench_case_t), intent(out) :: c
    integer :: idx
    idx = alloc_state()
    call build_stream_seeds(idx)
    call build_stream_mac(idx)
    call fill_payload(idx)
    call prebuild_lowlevel_aead_transcript(idx)
    call alloc_drain_pool(idx)
    c%name = name_in
    c%case_idx = idx
    c%payload_bytes = int(STREAM_TOTAL_BYTES, int64)
    c%run => run_lowlevel_decrypt_aead_io
  end subroutine

  subroutine make_lowlevel_encrypt_userloop(name_in, c)
    character(*),       intent(in)  :: name_in
    type(bench_case_t), intent(out) :: c
    integer :: idx
    idx = alloc_state()
    call build_stream_seeds(idx)
    call fill_payload(idx)
    c%name = name_in
    c%case_idx = idx
    c%payload_bytes = int(STREAM_TOTAL_BYTES, int64)
    c%run => run_lowlevel_encrypt_userloop
  end subroutine

  subroutine make_lowlevel_decrypt_userloop(name_in, c)
    character(*),       intent(in)  :: name_in
    type(bench_case_t), intent(out) :: c
    integer :: idx
    idx = alloc_state()
    call build_stream_seeds(idx)
    call fill_payload(idx)
    call prebuild_lowlevel_userloop_transcript(idx)
    c%name = name_in
    c%case_idx = idx
    c%payload_bytes = int(STREAM_TOTAL_BYTES, int64)
    c%run => run_lowlevel_decrypt_userloop
  end subroutine

  ! ---- Case-list assembly ---------------------------------------------

  subroutine build_cases(cs, n_out)
    type(bench_case_t), intent(out) :: cs(:)
    integer,            intent(out) :: n_out
    integer :: idx
    character(len=128) :: nm
    character(*), parameter :: PREFIX = "bench_triple_stream_areion512_1024bit_64mb"
    idx = 0
    idx = idx + 1
    nm = PREFIX // "_easy_encrypt_aead_io"
    call make_easy_encrypt_aead_io(nm, cs(idx))
    idx = idx + 1
    nm = PREFIX // "_easy_decrypt_aead_io"
    call make_easy_decrypt_aead_io(nm, cs(idx))
    idx = idx + 1
    nm = PREFIX // "_easy_encrypt_userloop"
    call make_easy_encrypt_userloop(nm, cs(idx))
    idx = idx + 1
    nm = PREFIX // "_easy_decrypt_userloop"
    call make_easy_decrypt_userloop(nm, cs(idx))
    idx = idx + 1
    nm = PREFIX // "_lowlevel_encrypt_aead_io"
    call make_lowlevel_encrypt_aead_io(nm, cs(idx))
    idx = idx + 1
    nm = PREFIX // "_lowlevel_decrypt_aead_io"
    call make_lowlevel_decrypt_aead_io(nm, cs(idx))
    idx = idx + 1
    nm = PREFIX // "_lowlevel_encrypt_userloop"
    call make_lowlevel_encrypt_userloop(nm, cs(idx))
    idx = idx + 1
    nm = PREFIX // "_lowlevel_decrypt_userloop"
    call make_lowlevel_decrypt_userloop(nm, cs(idx))
    n_out = idx
  end subroutine

end program bench_triple_stream
