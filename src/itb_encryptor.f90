! itb_encryptor.f90 -- safe RAII wrapper around the libitb Easy Mode
! encryptor handle. Mirrors the C binding's `itb_encryptor_*` surface
! and the Ada binding's `Itb.Encryptor` two-layer pattern.
!
! `type(itb_encryptor_t)` is the Fortran-side opaque encryptor. The
! `_t` suffix keeps the type-name distinct from the enclosing module
! `itb_encryptor` -- Fortran resolves bare `type(itb_encryptor)` to
! the module when the two scopes share a name.
!
! Three constructor paths (all subroutines, NOT functions, to avoid
! the finalization-on-function-return double-free trap that fires on
! a derived type carrying `final ::`):
!
!   1. Single-primitive:  `call new_itb_encryptor(e, "blake3", 1024, "hmac-blake3", 1)`
!   2. Mixed Single:      `call itb_encryptor_mixed_single(e, primN, primD, primS,        &
!                                                          1024, "hmac-blake3", primL=...)`
!   3. Mixed Triple:      `call itb_encryptor_mixed_triple(e, primN, primD1..3, primS1..3,&
!                                                          1024, "hmac-blake3", primL=...)`
!
! `prim_l` (the optional dedicated lockSeed primitive) carries
! Fortran's native `optional` attribute on Mixed Single / Mixed
! Triple constructors -- caller-side it appears as a trailing keyword
! argument; binding-side an absent argument routes `c_null_ptr` to
! the FFI's `primL` parameter, matching libitb's "no dedicated
! lockSeed primitive" semantics.
!
! Two-stage lifecycle release pattern (Fortran-only convention):
!
!   * Production code calls `e%destroy()` explicitly when finished --
!     this is the canonical lifecycle release. `destroy()` releases
!     the underlying libitb handle via `ITB_Easy_Free`.
!   * `e%close()` is the wipe-keying-material path -- routes through
!     `ITB_Easy_Close` to zero PRF / MAC / seed material on the Go
!     side, then marks the wrapper closed. Subsequent cipher / setter
!     / getter calls on a closed encryptor raise with
!     `STATUS_EASY_CLOSED` (raised via error stop) without round-
!     tripping libitb.
!   * `final :: itb_enc_final` is shipped as a safety net but its
!     invocation timing is not deterministic across gfortran / ifx /
!     nvfortran. Production code does not rely on the final hook
!     firing at any specific point. Errors raised inside `final` are
!     swallowed because the hook may fire at unpredictable program
!     scopes.
!
! Default-MAC override at the binding boundary. When the caller
! passes `mac_name = ""` (empty Fortran string) to any constructor,
! the wrapper substitutes `"hmac-blake3"` before forwarding to
! libitb. HMAC-BLAKE3 measures the lightest authenticated-mode
! overhead in the Easy bench surface, so the constructor-without-
! MAC path picks the lowest-cost authenticated MAC by default. To
! select a different MAC (e.g. `kmac256`), pass the canonical MAC
! name explicitly. The substitution is binding-side because
! `ITB_Easy_NewMixed` / `ITB_Easy_NewMixed3` do not auto-default
! empty `macName` Go-side -- only `ITB_Easy_New` does -- so the
! cross-binding contract is "wrapper owns the default" uniformly
! across all three constructors.
!
! Auto-couple semantics. Three rules govern the
! BitSoup / LockSoup / LockSeed overlay across both Easy Mode setters
! and the low-level process-wide knobs (libitb owns the cascade --
! the wrapper forwards each setter call verbatim):
!
!   1. **Setter-level: LockSoup -> BitSoup** (always, both modes).
!      `e%set_lock_soup(non-zero)` auto-engages BitSoup = 1;
!      `e%set_lock_seed(1)` auto-engages BitSoup = 1 + LockSoup = 1
!      (the dedicated lockSeed has no wire effect without the
!      overlay).
!   2. **Mode-dependent dispatch: Single Ouroboros activates the
!      overlay if EITHER flag is set.** In mode = 1, the Go-side
!      `splitForSingle` engages the lock-soup overlay if either
!      `BitSoup == 1` OR `LockSoup == 1`. Practical effect: in
!      Single Ouroboros, calling `e%set_bit_soup(1)` alone activates
!      the lock-soup overlay at encrypt time even though `LockSoup`
!      stays 0. In Triple Ouroboros (mode = 3), bit-soup and
!      lock-soup are independently meaningful -- bit-soup alone
!      splits payload bits without the PRF-keyed permutation overlay.
!   3. **Off-direction coercion while LockSeed active.** If
!      `LockSeed == 1`, calling `e%set_bit_soup(0)` or
!      `e%set_lock_soup(0)` is silently coerced to 1 to keep the
!      overlay engaged on the dedicated lockSeed channel; call
!      `e%set_lock_seed(0)` first to detach the lockSeed and fully
!      disengage. This is intentional libitb behaviour propagated
!      through the binding without filtering.
!
! Threading. Cipher methods, per-instance setters, and persistence
! calls write into per-instance state on the libitb side and are
! NOT safe to invoke concurrently against the same encryptor;
! external synchronisation is required when sharing one
! `itb_encryptor_t` value across threads. Distinct encryptor values,
! each owned by one thread, run independently against the libitb
! worker pool.

module itb_encryptor
  use itb_kinds
  use itb_sys
  use itb_strings, only: c_buffer_to_fortran_string, make_c_string
  use itb_errors,  only: STATUS_OK, STATUS_BAD_HANDLE, STATUS_BUFFER_TOO_SMALL, &
                          STATUS_EASY_CLOSED, raise_itb_error
  implicit none
  private

  public :: itb_encryptor_t
  public :: new_itb_encryptor
  public :: itb_encryptor_mixed_single
  public :: itb_encryptor_mixed_triple
  public :: itb_encryptor_peek_config
  public :: itb_last_mismatch_field

  type :: itb_encryptor_t
    private
    integer(itb_handle_kind) :: handle = itb_null_handle
    logical                  :: closed = .true.
  contains
    procedure :: encrypt           => itb_enc_encrypt
    procedure :: decrypt           => itb_enc_decrypt
    procedure :: encrypt_auth      => itb_enc_encrypt_auth
    procedure :: decrypt_auth      => itb_enc_decrypt_auth
    procedure :: close             => itb_enc_close
    procedure :: destroy           => itb_enc_destroy
    procedure :: set_lock_seed     => itb_enc_set_lock_seed
    procedure :: set_bit_soup      => itb_enc_set_bit_soup
    procedure :: set_lock_soup     => itb_enc_set_lock_soup
    procedure :: set_chunk_size    => itb_enc_set_chunk_size
    procedure :: set_nonce_bits    => itb_enc_set_nonce_bits
    procedure :: set_barrier_fill  => itb_enc_set_barrier_fill
    procedure :: primitive         => itb_enc_primitive
    procedure :: primitive_at      => itb_enc_primitive_at
    procedure :: mac_name          => itb_enc_mac_name
    procedure :: key_bits          => itb_enc_key_bits
    procedure :: mode              => itb_enc_mode
    procedure :: seed_count        => itb_enc_seed_count
    procedure :: nonce_bits        => itb_enc_nonce_bits
    procedure :: header_size       => itb_enc_header_size
    procedure :: has_prf_keys      => itb_enc_has_prf_keys
    procedure :: is_mixed          => itb_enc_is_mixed
    procedure :: mac_key           => itb_enc_mac_key
    procedure :: prf_key           => itb_enc_prf_key
    procedure :: seed_components   => itb_enc_seed_components
    procedure :: export_state      => itb_enc_export_state
    procedure :: import_state      => itb_enc_import_state
    procedure :: parse_chunk_len   => itb_enc_parse_chunk_len
    procedure :: raw_handle        => itb_enc_raw_handle
    procedure :: is_closed         => itb_enc_is_closed
    final     :: itb_enc_final
  end type

contains

  ! ----------------------------------------------------------------
  ! Default-MAC override (binding-side substitution)
  ! ----------------------------------------------------------------

  ! Fold an empty `mac_name` to the canonical `"hmac-blake3"`
  ! default before routing to libitb. The substitution lives on
  ! the binding side because `ITB_Easy_NewMixed` /
  ! `ITB_Easy_NewMixed3` do not auto-default empty `macName` on
  ! the Go side; uniform binding-side handling keeps the three
  ! constructors symmetric and matches the cross-binding contract.
  pure function resolved_mac_name(mac_name) result(s)
    character(*), intent(in) :: mac_name
    character(:), allocatable :: s
    if (len(mac_name) == 0) then
      s = "hmac-blake3"
    else
      s = mac_name
    end if
  end function

  ! ----------------------------------------------------------------
  ! Closed-state preflight
  ! ----------------------------------------------------------------

  ! Returns .true. when the encryptor has been closed or its handle
  ! has been released; callers raise STATUS_EASY_CLOSED before
  ! reaching for libitb so the canonical "encryptor has been closed"
  ! status surfaces regardless of whether the underlying handle slot
  ! has merely been zeroed (post-`close`) or has been released back
  ! to libitb (post-`destroy`).
  pure function is_closed_state(self) result(b)
    class(itb_encryptor_t), intent(in) :: self
    logical                            :: b
    b = self%closed .or. self%handle == itb_null_handle
  end function

  ! ----------------------------------------------------------------
  ! Constructors
  ! ----------------------------------------------------------------

  ! Single-primitive constructor. `primitive` is a canonical hash
  ! name from `itb_list_hashes()`; `key_bits` is the ITB key width
  ! (512 / 1024 / 2048; multiple of the primitive's native digest
  ! width). `mac_name = ""` triggers the libitb-side default-MAC
  ! override (`hmac-blake3`); pass a canonical MAC name explicitly
  ! to override. `mode` is 1 (Single Ouroboros) or 3 (Triple
  ! Ouroboros); other values raise with `STATUS_BAD_INPUT` (raised
  ! via error stop) through the libitb status-translation pipeline.
  subroutine new_itb_encryptor(e, primitive, key_bits, mac_name, mode)
    type(itb_encryptor_t), intent(out) :: e
    character(*),          intent(in)  :: primitive
    integer,               intent(in)  :: key_bits
    character(*),          intent(in)  :: mac_name
    integer,               intent(in)  :: mode
    character(kind=c_char), allocatable, target :: c_prim(:), c_mac(:)
    integer(itb_status_kind) :: rc

    e%handle = itb_null_handle
    e%closed = .true.

    call make_c_string(primitive, c_prim)
    call make_c_string(resolved_mac_name(mac_name), c_mac)
    rc = itb_easy_new_c(c_loc(c_prim),                     &
                         int(key_bits, c_int),              &
                         c_loc(c_mac),                      &
                         int(mode, c_int),                  &
                         e%handle)
    if (rc /= STATUS_OK) then
      e%handle = itb_null_handle
      e%closed = .true.
      call raise_itb_error(rc)
    end if
    e%closed = .false.
  end subroutine

  ! Mixed-primitive Single Ouroboros constructor. `prim_n` /
  ! `prim_d` / `prim_s` cover the noise / data / start slots (all
  ! required); `prim_l` is the optional dedicated lockSeed primitive
  ! -- pass via Fortran's `optional` keyword argument convention to
  ! request a 4th seed slot, omit for "no lockSeed primitive". All
  ! primitive names must resolve to the same native hash width;
  ! mixed widths raise with `STATUS_SEED_WIDTH_MIX` (raised via
  ! error stop).
  ! `mac_name = ""` triggers the binding's default-MAC override
  ! (resolves to `hmac-blake3` before crossing the FFI boundary).
  ! `prim_l` keeps the trailing position because Fortran's
  ! `optional` arguments must follow the non-optional ones; the
  ! FFI-side `primL` parameter sits at its canonical position
  ! between `prim_s` and `key_bits`, set via keyword call below.
  subroutine itb_encryptor_mixed_single(e, prim_n, prim_d, prim_s, &
                                        key_bits, mac_name, prim_l)
    type(itb_encryptor_t),   intent(out) :: e
    character(*),            intent(in)  :: prim_n
    character(*),            intent(in)  :: prim_d
    character(*),            intent(in)  :: prim_s
    integer,                 intent(in)  :: key_bits
    character(*),            intent(in)  :: mac_name
    character(*), optional,  intent(in)  :: prim_l
    character(kind=c_char), allocatable, target :: c_n(:), c_d(:), c_s(:)
    character(kind=c_char), allocatable, target :: c_l(:), c_mac(:)
    type(c_ptr) :: l_ptr
    integer(itb_status_kind) :: rc

    e%handle = itb_null_handle
    e%closed = .true.

    call make_c_string(prim_n,  c_n)
    call make_c_string(prim_d,  c_d)
    call make_c_string(prim_s,  c_s)
    call make_c_string(resolved_mac_name(mac_name), c_mac)

    if (present(prim_l)) then
      call make_c_string(prim_l, c_l)
      l_ptr = c_loc(c_l)
    else
      l_ptr = c_null_ptr
    end if

    rc = itb_easy_new_mixed_c(c_loc(c_n), c_loc(c_d), c_loc(c_s), &
                                l_ptr,                              &
                                int(key_bits, c_int),               &
                                c_loc(c_mac),                       &
                                e%handle)
    if (rc /= STATUS_OK) then
      e%handle = itb_null_handle
      e%closed = .true.
      call raise_itb_error(rc)
    end if
    e%closed = .false.
  end subroutine

  ! Mixed-primitive Triple Ouroboros constructor. Allocates seven
  ! seed slots (noise + 3 data + 3 start); `prim_l` is the optional
  ! dedicated lockSeed primitive following the same `optional`
  ! convention as `itb_encryptor_mixed_single`. All eight primitive
  ! names (when `prim_l` is present) must resolve to the same native
  ! hash width.
  subroutine itb_encryptor_mixed_triple(e, prim_n,                       &
                                          prim_d1, prim_d2, prim_d3,     &
                                          prim_s1, prim_s2, prim_s3,     &
                                          key_bits, mac_name, prim_l)
    type(itb_encryptor_t),   intent(out) :: e
    character(*),            intent(in)  :: prim_n
    character(*),            intent(in)  :: prim_d1, prim_d2, prim_d3
    character(*),            intent(in)  :: prim_s1, prim_s2, prim_s3
    integer,                 intent(in)  :: key_bits
    character(*),            intent(in)  :: mac_name
    character(*), optional,  intent(in)  :: prim_l
    character(kind=c_char), allocatable, target :: c_n(:), c_d1(:), c_d2(:), c_d3(:)
    character(kind=c_char), allocatable, target :: c_s1(:), c_s2(:), c_s3(:)
    character(kind=c_char), allocatable, target :: c_l(:), c_mac(:)
    type(c_ptr) :: l_ptr
    integer(itb_status_kind) :: rc

    e%handle = itb_null_handle
    e%closed = .true.

    call make_c_string(prim_n,  c_n)
    call make_c_string(prim_d1, c_d1)
    call make_c_string(prim_d2, c_d2)
    call make_c_string(prim_d3, c_d3)
    call make_c_string(prim_s1, c_s1)
    call make_c_string(prim_s2, c_s2)
    call make_c_string(prim_s3, c_s3)
    call make_c_string(resolved_mac_name(mac_name), c_mac)

    if (present(prim_l)) then
      call make_c_string(prim_l, c_l)
      l_ptr = c_loc(c_l)
    else
      l_ptr = c_null_ptr
    end if

    rc = itb_easy_new_mixed3_c(c_loc(c_n),                                 &
                                 c_loc(c_d1), c_loc(c_d2), c_loc(c_d3),    &
                                 c_loc(c_s1), c_loc(c_s2), c_loc(c_s3),    &
                                 l_ptr,                                    &
                                 int(key_bits, c_int),                     &
                                 c_loc(c_mac),                             &
                                 e%handle)
    if (rc /= STATUS_OK) then
      e%handle = itb_null_handle
      e%closed = .true.
      call raise_itb_error(rc)
    end if
    e%closed = .false.
  end subroutine

  ! ----------------------------------------------------------------
  ! Lifecycle
  ! ----------------------------------------------------------------

  ! Wipes PRF / MAC / seed material on the Go side via
  ! `ITB_Easy_Close` and marks the wrapper closed. Idempotent --
  ! repeated calls return without raising. Subsequent cipher /
  ! setter / getter calls return `STATUS_EASY_CLOSED`. The wrapper
  ! struct itself remains valid; release the underlying handle
  ! deterministically via `e%destroy()`.
  subroutine itb_enc_close(self)
    class(itb_encryptor_t), intent(inout) :: self
    integer(itb_status_kind) :: rc

    if (is_closed_state(self)) then
      self%closed = .true.
      return
    end if
    rc = itb_easy_close_c(self%handle)
    self%closed = .true.
    if (rc /= STATUS_OK .and. rc /= STATUS_BAD_HANDLE) call raise_itb_error(rc)
  end subroutine

  ! Releases the libitb handle via `ITB_Easy_Free` and marks the
  ! wrapper closed. Idempotent. Canonical lifecycle release path
  ! for production code (final-hook timing is non-deterministic
  ! across Fortran compilers).
  subroutine itb_enc_destroy(self)
    class(itb_encryptor_t), intent(inout) :: self
    integer(itb_status_kind) :: rc

    if (self%closed) then
      self%handle = itb_null_handle
      return
    end if
    if (self%handle /= itb_null_handle) then
      rc = itb_easy_free_c(self%handle)
      if (rc /= STATUS_OK .and. rc /= STATUS_BAD_HANDLE) call raise_itb_error(rc)
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  ! Safety-net hook -- non-deterministic across compilers. Errors
  ! are swallowed because the hook may fire at unpredictable program
  ! scopes (temporaries during reallocation, end-of-program-unit
  ! deferral, re-entry from another final).
  subroutine itb_enc_final(self)
    type(itb_encryptor_t), intent(inout) :: self
    if (self%closed) return
    if (self%handle /= itb_null_handle) then
      block
        integer(itb_status_kind) :: rc
        rc = itb_easy_free_c(self%handle)
      end block
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  ! ----------------------------------------------------------------
  ! Cipher entry points
  ! ----------------------------------------------------------------

  ! Single-call path -- pre-allocate a generous upper bound on the
  ! output size, call libitb once, and truncate the result array to
  ! the actual returned length via `move_alloc` with an array-
  ! assignment copy. The probe FFI round-trip (NULL pointer + cap = 0
  ! discovery call) is skipped; the formula
  ! `max(131072, ptlen + ptlen/4 + 131072)` covers every cell in the
  ! mode / nonce-bits / barrier-fill matrix. Under the default
  ! barrier-fill of 1 the absolute ratio sits at most around 1.155;
  ! under bf=32 the ratio rises to ~1.346 around the 1 MiB payload
  ! region, and the 128 KiB pad absorbs the residual margin the
  ! 1.25x multiplier alone does not cover (~100 KiB at 1 MiB, less
  ! at smaller and larger sizes). Short payloads through Triple
  ! Ouroboros and the authenticated variants can exhibit
  ! substantially larger fixed-overhead expansion at very small
  ! input sizes (Triple + auth-MAC + bf=32 at ptlen=1 ~ 35 KiB); the
  ! 128 KiB floor handles those without triggering the retry path.
  ! The rare `STATUS_BUFFER_TOO_SMALL` from the first call surfaces
  ! the libitb-reported required size in `out_len`, and a single
  ! resize-and-retry recovers without invoking the explicit two-call
  ! probe shape. The byte-by-byte truncation loop is replaced by a
  ! Fortran array assignment, which compilers vectorise to a single
  ! memcpy.

  function itb_enc_encrypt(self, plaintext) result(ciphertext)
    class(itb_encryptor_t),                     intent(in) :: self
    integer(itb_byte_kind), target, contiguous, intent(in) :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: ciphertext(:)
    integer(itb_size_kind) :: ptlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    ptlen = int(size(plaintext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ptlen > 0) in_ptr = c_loc(plaintext)

    cap = max(131072_itb_size_kind, &
               ptlen + ptlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (ciphertext(cap))

    out_len = 0_itb_size_kind
    rc = itb_easy_encrypt_c(self%handle, in_ptr, ptlen, &
                              c_loc(ciphertext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      ! Pre-allocation was too tight (small payloads through Triple /
      ! authenticated variants can exceed the 1.25x bulk-rate bound).
      ! `out_len` carries the libitb-reported required size; resize
      ! exactly and retry once.
      cap = out_len
      deallocate (ciphertext)
      allocate (ciphertext(cap))
      rc = itb_easy_encrypt_c(self%handle, in_ptr, ptlen, &
                                c_loc(ciphertext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    ! Truncate to actual length. Allocatable arrays cannot be resized
    ! in place; allocate a right-sized companion, copy via array
    ! assignment, and swap with `move_alloc`.
    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = ciphertext(1:out_len)
      call move_alloc(trimmed, ciphertext)
    end block
  end function

  function itb_enc_decrypt(self, ciphertext) result(plaintext)
    class(itb_encryptor_t),                     intent(in) :: self
    integer(itb_byte_kind), target, contiguous, intent(in) :: ciphertext(:)
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_size_kind) :: ctlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    ctlen = int(size(ciphertext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ctlen > 0) in_ptr = c_loc(ciphertext)

    cap = max(131072_itb_size_kind, &
               ctlen + ctlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (plaintext(cap))

    out_len = 0_itb_size_kind
    rc = itb_easy_decrypt_c(self%handle, in_ptr, ctlen, &
                              c_loc(plaintext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      cap = out_len
      deallocate (plaintext)
      allocate (plaintext(cap))
      rc = itb_easy_decrypt_c(self%handle, in_ptr, ctlen, &
                                c_loc(plaintext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = plaintext(1:out_len)
      call move_alloc(trimmed, plaintext)
    end block
  end function

  function itb_enc_encrypt_auth(self, plaintext) result(ciphertext)
    class(itb_encryptor_t),                     intent(in) :: self
    integer(itb_byte_kind), target, contiguous, intent(in) :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: ciphertext(:)
    integer(itb_size_kind) :: ptlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    ptlen = int(size(plaintext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ptlen > 0) in_ptr = c_loc(plaintext)

    cap = max(131072_itb_size_kind, &
               ptlen + ptlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (ciphertext(cap))

    out_len = 0_itb_size_kind
    rc = itb_easy_encrypt_auth_c(self%handle, in_ptr, ptlen, &
                                   c_loc(ciphertext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      cap = out_len
      deallocate (ciphertext)
      allocate (ciphertext(cap))
      rc = itb_easy_encrypt_auth_c(self%handle, in_ptr, ptlen, &
                                     c_loc(ciphertext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = ciphertext(1:out_len)
      call move_alloc(trimmed, ciphertext)
    end block
  end function

  function itb_enc_decrypt_auth(self, ciphertext) result(plaintext)
    class(itb_encryptor_t),                     intent(in) :: self
    integer(itb_byte_kind), target, contiguous, intent(in) :: ciphertext(:)
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_size_kind) :: ctlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    ctlen = int(size(ciphertext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ctlen > 0) in_ptr = c_loc(ciphertext)

    cap = max(131072_itb_size_kind, &
               ctlen + ctlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (plaintext(cap))

    out_len = 0_itb_size_kind
    rc = itb_easy_decrypt_auth_c(self%handle, in_ptr, ctlen, &
                                   c_loc(plaintext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      cap = out_len
      deallocate (plaintext)
      allocate (plaintext(cap))
      rc = itb_easy_decrypt_auth_c(self%handle, in_ptr, ctlen, &
                                     c_loc(plaintext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = plaintext(1:out_len)
      call move_alloc(trimmed, plaintext)
    end block
  end function

  ! ----------------------------------------------------------------
  ! Per-instance configuration setters
  ! ----------------------------------------------------------------

  subroutine itb_enc_set_nonce_bits(self, n)
    class(itb_encryptor_t), intent(inout) :: self
    integer,                intent(in)    :: n
    integer(itb_status_kind) :: rc
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    rc = itb_easy_set_nonce_bits_c(self%handle, int(n, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_enc_set_barrier_fill(self, n)
    class(itb_encryptor_t), intent(inout) :: self
    integer,                intent(in)    :: n
    integer(itb_status_kind) :: rc
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    rc = itb_easy_set_barrier_fill_c(self%handle, int(n, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_enc_set_bit_soup(self, mode)
    class(itb_encryptor_t), intent(inout) :: self
    integer,                intent(in)    :: mode
    integer(itb_status_kind) :: rc
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    rc = itb_easy_set_bit_soup_c(self%handle, int(mode, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_enc_set_lock_soup(self, mode)
    class(itb_encryptor_t), intent(inout) :: self
    integer,                intent(in)    :: mode
    integer(itb_status_kind) :: rc
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    rc = itb_easy_set_lock_soup_c(self%handle, int(mode, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_enc_set_lock_seed(self, mode)
    class(itb_encryptor_t), intent(inout) :: self
    integer,                intent(in)    :: mode
    integer(itb_status_kind) :: rc
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    rc = itb_easy_set_lock_seed_c(self%handle, int(mode, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_enc_set_chunk_size(self, n)
    class(itb_encryptor_t), intent(inout) :: self
    integer,                intent(in)    :: n
    integer(itb_status_kind) :: rc
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    rc = itb_easy_set_chunk_size_c(self%handle, int(n, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  ! ----------------------------------------------------------------
  ! Read-only accessors
  ! ----------------------------------------------------------------

  function itb_enc_primitive(self) result(s)
    class(itb_encryptor_t), intent(in) :: self
    character(:), allocatable :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    out_len = 0_itb_size_kind
    rc = itb_easy_primitive_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    cap = max(out_len + 1_itb_size_kind, 64_itb_size_kind)
    allocate (buf(cap))
    rc = itb_easy_primitive_c(self%handle, c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

  function itb_enc_primitive_at(self, slot) result(s)
    class(itb_encryptor_t), intent(in) :: self
    integer,                intent(in) :: slot
    character(:), allocatable :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    out_len = 0_itb_size_kind
    rc = itb_easy_primitive_at_c(self%handle, int(slot, c_int), &
                                   c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    cap = max(out_len + 1_itb_size_kind, 64_itb_size_kind)
    allocate (buf(cap))
    rc = itb_easy_primitive_at_c(self%handle, int(slot, c_int), &
                                   c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

  function itb_enc_mac_name(self) result(s)
    class(itb_encryptor_t), intent(in) :: self
    character(:), allocatable :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    out_len = 0_itb_size_kind
    rc = itb_easy_mac_name_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    cap = max(out_len + 1_itb_size_kind, 64_itb_size_kind)
    allocate (buf(cap))
    rc = itb_easy_mac_name_c(self%handle, c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

  ! Inverted-signature getters: the C return value carries the data
  ! and the `outStatus` int* carries the status code. Mirrors
  ! `itb_seed_width`'s shape.
  function itb_enc_key_bits(self) result(v)
    class(itb_encryptor_t), intent(in) :: self
    integer(itb_int32_kind)            :: v
    integer(itb_status_kind) :: st
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    v = itb_easy_key_bits_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  function itb_enc_mode(self) result(v)
    class(itb_encryptor_t), intent(in) :: self
    integer(itb_int32_kind)            :: v
    integer(itb_status_kind) :: st
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    v = itb_easy_mode_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  function itb_enc_seed_count(self) result(v)
    class(itb_encryptor_t), intent(in) :: self
    integer(itb_int32_kind)            :: v
    integer(itb_status_kind) :: st
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    v = itb_easy_seed_count_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  function itb_enc_nonce_bits(self) result(v)
    class(itb_encryptor_t), intent(in) :: self
    integer(itb_int32_kind)            :: v
    integer(itb_status_kind) :: st
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    v = itb_easy_nonce_bits_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  function itb_enc_header_size(self) result(v)
    class(itb_encryptor_t), intent(in) :: self
    integer(itb_int32_kind)            :: v
    integer(itb_status_kind) :: st
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    v = itb_easy_header_size_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  function itb_enc_has_prf_keys(self) result(b)
    class(itb_encryptor_t), intent(in) :: self
    logical                            :: b
    integer(itb_status_kind) :: st
    integer(itb_int32_kind) :: v
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    v = itb_easy_has_prf_keys_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
    b = (v /= 0)
  end function

  function itb_enc_is_mixed(self) result(b)
    class(itb_encryptor_t), intent(in) :: self
    logical                            :: b
    integer(itb_status_kind) :: st
    integer(itb_int32_kind) :: v
    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)
    v = itb_easy_is_mixed_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
    b = (v /= 0)
  end function

  ! ----------------------------------------------------------------
  ! Material getter (defensive copy)
  ! ----------------------------------------------------------------

  function itb_enc_mac_key(self) result(key)
    class(itb_encryptor_t), intent(in) :: self
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer :: i

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    out_len = 0_itb_size_kind
    rc = itb_easy_mac_key_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (key(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_easy_mac_key_c(self%handle, c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (key(int(out_len)))
    do i = 1, int(out_len)
      key(i) = scratch(i)
    end do
  end function

  ! Returns the per-slot PRF key (32 bytes) for primitives that carry
  ! one. SipHash-2-4 is the only Easy Mode primitive without an
  ! internal PRF key (its key material is consumed directly per pixel
  ! from seed components); calling `prf_key` on a SipHash encryptor
  ! returns a zero-length array.
  function itb_enc_prf_key(self, slot) result(key)
    class(itb_encryptor_t), intent(in) :: self
    integer,                intent(in) :: slot
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer :: i

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    out_len = 0_itb_size_kind
    rc = itb_easy_prf_key_c(self%handle, int(slot, c_int), &
                              c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (key(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_easy_prf_key_c(self%handle, int(slot, c_int), &
                              c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (key(int(out_len)))
    do i = 1, int(out_len)
      key(i) = scratch(i)
    end do
  end function

  ! Returns the per-slot uint64 seed components for the encryptor.
  ! `slot` ranges over 0..seed_count()-1 (3 slots for Single, 7 slots
  ! for Triple, plus an extra slot for the dedicated lockSeed when
  ! `set_lock_seed(1)` is engaged). Out-of-range slot raises
  ! `STATUS_BAD_INPUT`.
  function itb_enc_seed_components(self, slot) result(comps)
    class(itb_encryptor_t), intent(in) :: self
    integer,                intent(in) :: slot
    integer(itb_u64_kind), allocatable :: comps(:)
    integer(itb_u64_kind), allocatable, target :: scratch(:)
    integer(itb_int32_kind) :: cap_count, out_count
    integer(itb_status_kind) :: rc
    integer :: i

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    out_count = 0
    rc = itb_easy_seed_components_c(self%handle, int(slot, c_int), &
                                      c_null_ptr, 0, out_count)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_count <= 0) then
      allocate (comps(0))
      return
    end if
    cap_count = out_count
    allocate (scratch(cap_count))
    rc = itb_easy_seed_components_c(self%handle, int(slot, c_int), &
                                      c_loc(scratch), cap_count, out_count)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (comps(out_count))
    do i = 1, out_count
      comps(i) = scratch(i)
    end do
  end function

  ! ----------------------------------------------------------------
  ! Persistence
  ! ----------------------------------------------------------------

  ! Serialises the encryptor's full state (PRF keys, seed components,
  ! MAC key, dedicated lockSeed material when active) as a JSON blob.
  ! Per-instance configuration knobs (NonceBits, BarrierFill,
  ! BitSoup, LockSoup, ChunkSize) are NOT carried in the v1 blob;
  ! both sides communicate them via deployment config. LockSeed is
  ! carried because activating it changes the structural seed count.
  function itb_enc_export_state(self) result(blob)
    class(itb_encryptor_t), intent(in) :: self
    integer(itb_byte_kind), allocatable :: blob(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer :: i

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    out_len = 0_itb_size_kind
    rc = itb_easy_export_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (blob(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_easy_export_c(self%handle, c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (blob(int(out_len)))
    do i = 1, int(out_len)
      blob(i) = scratch(i)
    end do
  end function

  ! Replaces the encryptor's PRF keys, seed components, MAC key, and
  ! (optionally) dedicated lockSeed material with the values carried
  ! in a JSON blob produced by a prior `e%export_state()` call. On
  ! any failure the encryptor's pre-import state is unchanged (the
  ! underlying Go-side import is transactional). Mismatch on
  ! primitive / key_bits / mode / mac raises with
  ! `STATUS_EASY_MISMATCH` (raised via error stop); the offending
  ! JSON field name is retrievable via `itb_last_mismatch_field()`.
  subroutine itb_enc_import_state(self, blob)
    class(itb_encryptor_t),                       intent(inout) :: self
    integer(itb_byte_kind), target, contiguous,   intent(in)    :: blob(:)
    integer(itb_size_kind) :: blob_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: blob_ptr

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    blob_len = int(size(blob), itb_size_kind)
    blob_ptr = c_null_ptr
    if (blob_len > 0) blob_ptr = c_loc(blob)

    rc = itb_easy_import_c(self%handle, blob_ptr, blob_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  ! ----------------------------------------------------------------
  ! Streaming helpers
  ! ----------------------------------------------------------------

  ! Per-instance counterpart of `itb_parse_chunk_len`. Inspects the
  ! fixed-size [nonce(N) || width(2) || height(2)] header of a
  ! ciphertext chunk produced by this encryptor and returns the
  ! total chunk length on the wire. Buffer must contain at least
  ! `e%header_size()` bytes; only the header is consulted, the body
  ! bytes need not be present.
  function itb_enc_parse_chunk_len(self, header) result(chunk_len)
    class(itb_encryptor_t),                       intent(in) :: self
    integer(itb_byte_kind), target, contiguous,   intent(in) :: header(:)
    integer(itb_size_kind) :: chunk_len
    integer(itb_size_kind) :: hlen, out_chunk
    integer(itb_status_kind) :: rc
    type(c_ptr) :: hdr_ptr

    if (is_closed_state(self)) call raise_itb_error(STATUS_EASY_CLOSED)

    hlen = int(size(header), itb_size_kind)
    hdr_ptr = c_null_ptr
    if (hlen > 0) hdr_ptr = c_loc(header)

    out_chunk = 0_itb_size_kind
    rc = itb_easy_parse_chunk_len_c(self%handle, hdr_ptr, hlen, out_chunk)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
    chunk_len = out_chunk
  end function

  ! ----------------------------------------------------------------
  ! Raw-handle / closed-state introspection (escape hatches)
  ! ----------------------------------------------------------------

  function itb_enc_raw_handle(self) result(h)
    class(itb_encryptor_t), intent(in) :: self
    integer(itb_handle_kind)           :: h
    h = self%handle
  end function

  function itb_enc_is_closed(self) result(b)
    class(itb_encryptor_t), intent(in) :: self
    logical                            :: b
    b = self%closed
  end function

  ! ----------------------------------------------------------------
  ! Free subroutines / functions
  ! ----------------------------------------------------------------

  ! Parses a state blob's metadata (primitive, key_bits, mode,
  ! mac_name) without performing full validation, allowing a caller
  ! to inspect a saved blob before constructing a matching
  ! encryptor. Two-call probe internally: discovers required string
  ! sizes via the libitb-side `*outLen` outputs, allocates buffers,
  ! reads the values, NUL-strips both names. Raises with
  ! `STATUS_EASY_MALFORMED` (raised via error stop) on parse failure
  ! / kind mismatch / too-new version / unknown mode value.
  !
  ! Asymmetry vs `e%import_state`: the peek path conflates "version
  ! too new" with "malformed" and surfaces both as
  ! `STATUS_EASY_MALFORMED`; only `import_state` differentiates the
  ! two via the dedicated `STATUS_EASY_VERSION_TOO_NEW` status.
  subroutine itb_encryptor_peek_config(blob, primitive, key_bits, mode, mac_name)
    integer(itb_byte_kind), target, contiguous, intent(in)  :: blob(:)
    character(:), allocatable,                  intent(out) :: primitive
    integer(itb_int32_kind),                    intent(out) :: key_bits
    integer(itb_int32_kind),                    intent(out) :: mode
    character(:), allocatable,                  intent(out) :: mac_name
    character(kind=c_char), allocatable, target :: prim_buf(:), mac_buf(:)
    integer(itb_size_kind) :: blob_len, prim_cap, mac_cap, prim_len, mac_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: blob_ptr

    blob_len = int(size(blob), itb_size_kind)
    blob_ptr = c_null_ptr
    if (blob_len > 0) blob_ptr = c_loc(blob)

    key_bits = 0
    mode     = 0

    ! Probe both string sizes first.
    prim_len = 0_itb_size_kind
    mac_len  = 0_itb_size_kind
    rc = itb_easy_peek_config_c(blob_ptr, blob_len,                  &
                                  c_null_ptr, 0_itb_size_kind, prim_len, &
                                  key_bits, mode,                    &
                                  c_null_ptr, 0_itb_size_kind, mac_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    prim_cap = max(prim_len + 1_itb_size_kind, 1_itb_size_kind)
    mac_cap  = max(mac_len  + 1_itb_size_kind, 1_itb_size_kind)
    allocate (prim_buf(prim_cap))
    allocate (mac_buf(mac_cap))

    rc = itb_easy_peek_config_c(blob_ptr, blob_len,                 &
                                  c_loc(prim_buf), prim_cap, prim_len, &
                                  key_bits, mode,                   &
                                  c_loc(mac_buf), mac_cap, mac_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    call c_buffer_to_fortran_string(prim_buf, prim_len, primitive)
    call c_buffer_to_fortran_string(mac_buf,  mac_len,  mac_name)
  end subroutine

  ! Reads the offending JSON field name from the most recent
  ! `e%import_state()` call that returned `STATUS_EASY_MISMATCH` on
  ! this thread. Empty string when the most recent failure was not
  ! a mismatch (libitb's TLS slot reflects the calling thread's
  ! most recent libitb error).
  function itb_last_mismatch_field() result(s)
    character(:), allocatable :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    out_len = 0_itb_size_kind
    rc = itb_easy_last_mismatch_field_c(c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) then
      ! Diagnostic itself is unreadable -- return empty string.
      s = ""
      return
    end if
    if (out_len == 0) then
      s = ""
      return
    end if

    cap = out_len + 1_itb_size_kind
    allocate (buf(cap))
    rc = itb_easy_last_mismatch_field_c(c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) then
      s = ""
      return
    end if
    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

end module itb_encryptor
