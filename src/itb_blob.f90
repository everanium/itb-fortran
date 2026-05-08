! itb_blob.f90 -- safe RAII wrappers around the libitb Blob128 /
! Blob256 / Blob512 persistence handles.
!
! `type(itb_blob128_t)` / `type(itb_blob256_t)` / `type(itb_blob512_t)`
! are the Fortran-side opaque Blob containers; each carries a `_t`
! suffix to distinguish from the enclosing module name (Fortran
! resolves bare `type(itb_blob128)` to the module when the type and
! module share a name, breaking the `final` hook in subtle ways).
!
! A Blob is a width-typed bag of seed material plus optional MAC
! parameters that serialises to / deserialises from a self-describing
! JSON envelope (Single mode: `export` / `import`; Triple mode:
! `export_3` / `import_3`). The width of a Blob is fixed at
! construction (128 / 256 / 512); mismatching the wire blob's width
! against the receiving Blob's width raises with
! `STATUS_BLOB_MODE_MISMATCH` (raised via error stop).
!
! Slot indexing follows the libitb convention: 0 = noise, 1 = data,
! 2 = start (Single mode), 3 = optional dedicated lockSeed (any mode),
! 4..6 = data1 / data2 / data3, 7..9 = start1 / start2 / start3
! (Triple mode). Setters / getters do not validate the slot index
! against the current mode -- libitb owns that cascade and the Blob
! is mode-agnostic until export / import time.
!
! Construction. Each Blob type has a subroutine constructor with
! `intent(out)`:
!
!   call new_itb_blob128(b)
!   call new_itb_blob256(b)
!   call new_itb_blob512(b)
!
! The freshly constructed Blob is empty. Populate it via `set_*`
! methods to prepare for `export` / `export_3`, or call
! `import` / `import_3` to load material from a persisted blob.
!
! Subroutine-with-`intent(out)` is the canonical Fortran idiom for
! handle-owning derived types -- avoids the function-result temporary
! that the `final ::` hook would double-finalise on return.
!
! Two-stage lifecycle release pattern:
!
!   * Production code calls `b%destroy()` explicitly when finished --
!     idempotent, releases the underlying libitb handle via
!     `ITB_Blob_Free`.
!   * `final :: itb_blob*_final` is shipped as a safety net but its
!     invocation timing is not deterministic across gfortran / ifx /
!     nvfortran. Errors raised inside `final` are swallowed because
!     the hook may fire at unpredictable program scopes.
!
! Closed-state preflight. After `b%destroy()` the wrapper marks
! itself closed; subsequent method calls return / raise
! `STATUS_BAD_HANDLE` without round-tripping libitb. The Blob has no
! separate `close()` operation -- there is no Go-side keying material
! to wipe (the Blob carries copies of the encryptor's material rather
! than live PRF state), so destroy is the single release path.
!
! Threading. Blob handles are not safe to share across threads
! without external synchronisation -- the per-handle setter / getter
! calls mutate state on the libitb side. Distinct handles, each owned
! by one thread, run independently. Same cross-binding contract as
! the Easy Mode encryptor's per-instance discipline.
!
! Export options. `export` / `export_3` accept an optional `opts`
! integer bitmask defaulting to 0; combine the binding-side constants
! `ITB_BLOB_OPT_LOCKSEED` (emit the dedicated-lockSeed slot) and
! `ITB_BLOB_OPT_MAC` (emit MAC key + name) with bitwise OR to opt
! into the corresponding wire fields. The default of 0 emits the
! base seed material only.

module itb_blob
  use itb_kinds
  use itb_sys
  use itb_strings, only: c_buffer_to_fortran_string, make_c_string
  use itb_errors,  only: STATUS_OK, STATUS_BAD_HANDLE, STATUS_BUFFER_TOO_SMALL, &
                          raise_itb_error
  implicit none
  private

  public :: itb_blob128_t
  public :: itb_blob256_t
  public :: itb_blob512_t
  public :: new_itb_blob128
  public :: new_itb_blob256
  public :: new_itb_blob512

  ! Export-options bitmask. Combine via bitwise OR (`ior`) on the
  ! `opts` argument to `export` / `export_3`.
  integer, parameter, public :: ITB_BLOB_OPT_LOCKSEED = 1   ! 1 << 0
  integer, parameter, public :: ITB_BLOB_OPT_MAC      = 2   ! 1 << 1

  type :: itb_blob128_t
    private
    integer(itb_handle_kind) :: handle = itb_null_handle
    logical                  :: closed = .true.
  contains
    procedure :: width          => itb_blob128_width
    procedure :: mode           => itb_blob128_mode
    procedure :: set_key        => itb_blob128_set_key
    procedure :: get_key        => itb_blob128_get_key
    procedure :: set_components => itb_blob128_set_components
    procedure :: get_components => itb_blob128_get_components
    procedure :: set_mac_key    => itb_blob128_set_mac_key
    procedure :: get_mac_key    => itb_blob128_get_mac_key
    procedure :: set_mac_name   => itb_blob128_set_mac_name
    procedure :: get_mac_name   => itb_blob128_get_mac_name
    procedure :: export         => itb_blob128_export
    procedure :: export_3       => itb_blob128_export_3
    procedure :: import         => itb_blob128_import
    procedure :: import_3       => itb_blob128_import_3
    procedure :: destroy        => itb_blob128_destroy
    procedure :: raw_handle     => itb_blob128_raw_handle
    procedure :: is_closed      => itb_blob128_is_closed
    final     :: itb_blob128_final
  end type

  type :: itb_blob256_t
    private
    integer(itb_handle_kind) :: handle = itb_null_handle
    logical                  :: closed = .true.
  contains
    procedure :: width          => itb_blob256_width
    procedure :: mode           => itb_blob256_mode
    procedure :: set_key        => itb_blob256_set_key
    procedure :: get_key        => itb_blob256_get_key
    procedure :: set_components => itb_blob256_set_components
    procedure :: get_components => itb_blob256_get_components
    procedure :: set_mac_key    => itb_blob256_set_mac_key
    procedure :: get_mac_key    => itb_blob256_get_mac_key
    procedure :: set_mac_name   => itb_blob256_set_mac_name
    procedure :: get_mac_name   => itb_blob256_get_mac_name
    procedure :: export         => itb_blob256_export
    procedure :: export_3       => itb_blob256_export_3
    procedure :: import         => itb_blob256_import
    procedure :: import_3       => itb_blob256_import_3
    procedure :: destroy        => itb_blob256_destroy
    procedure :: raw_handle     => itb_blob256_raw_handle
    procedure :: is_closed      => itb_blob256_is_closed
    final     :: itb_blob256_final
  end type

  type :: itb_blob512_t
    private
    integer(itb_handle_kind) :: handle = itb_null_handle
    logical                  :: closed = .true.
  contains
    procedure :: width          => itb_blob512_width
    procedure :: mode           => itb_blob512_mode
    procedure :: set_key        => itb_blob512_set_key
    procedure :: get_key        => itb_blob512_get_key
    procedure :: set_components => itb_blob512_set_components
    procedure :: get_components => itb_blob512_get_components
    procedure :: set_mac_key    => itb_blob512_set_mac_key
    procedure :: get_mac_key    => itb_blob512_get_mac_key
    procedure :: set_mac_name   => itb_blob512_set_mac_name
    procedure :: get_mac_name   => itb_blob512_get_mac_name
    procedure :: export         => itb_blob512_export
    procedure :: export_3       => itb_blob512_export_3
    procedure :: import         => itb_blob512_import
    procedure :: import_3       => itb_blob512_import_3
    procedure :: destroy        => itb_blob512_destroy
    procedure :: raw_handle     => itb_blob512_raw_handle
    procedure :: is_closed      => itb_blob512_is_closed
    final     :: itb_blob512_final
  end type

contains

  ! ----------------------------------------------------------------
  ! Closed-state preflight (shared across all three Blob widths)
  ! ----------------------------------------------------------------

  ! Returns .true. when the Blob has been destroyed or its handle
  ! has been released; callers raise STATUS_BAD_HANDLE before
  ! reaching for libitb so the canonical "Blob handle is invalid"
  ! status surfaces regardless of how the wrapper got into the
  ! closed slot. Blobs do not have a separate STATUS_BLOB_CLOSED in
  ! the libitb registry; STATUS_BAD_HANDLE is the canonical code.
  pure function blob128_is_closed_state(self) result(b)
    class(itb_blob128_t), intent(in) :: self
    logical                          :: b
    b = self%closed .or. self%handle == itb_null_handle
  end function

  pure function blob256_is_closed_state(self) result(b)
    class(itb_blob256_t), intent(in) :: self
    logical                          :: b
    b = self%closed .or. self%handle == itb_null_handle
  end function

  pure function blob512_is_closed_state(self) result(b)
    class(itb_blob512_t), intent(in) :: self
    logical                          :: b
    b = self%closed .or. self%handle == itb_null_handle
  end function

  ! ----------------------------------------------------------------
  ! Constructors
  ! ----------------------------------------------------------------

  ! Allocate a fresh empty Blob128. Caller populates it via the
  ! `set_*` methods (to prepare for `export` / `export_3`) or via
  ! `import` / `import_3` (to load material from a persisted blob).
  subroutine new_itb_blob128(b)
    type(itb_blob128_t), intent(out) :: b
    integer(itb_status_kind) :: rc

    b%handle = itb_null_handle
    b%closed = .true.

    rc = itb_blob128_new_c(b%handle)
    if (rc /= STATUS_OK) then
      b%handle = itb_null_handle
      b%closed = .true.
      call raise_itb_error(rc)
    end if
    b%closed = .false.
  end subroutine

  subroutine new_itb_blob256(b)
    type(itb_blob256_t), intent(out) :: b
    integer(itb_status_kind) :: rc

    b%handle = itb_null_handle
    b%closed = .true.

    rc = itb_blob256_new_c(b%handle)
    if (rc /= STATUS_OK) then
      b%handle = itb_null_handle
      b%closed = .true.
      call raise_itb_error(rc)
    end if
    b%closed = .false.
  end subroutine

  subroutine new_itb_blob512(b)
    type(itb_blob512_t), intent(out) :: b
    integer(itb_status_kind) :: rc

    b%handle = itb_null_handle
    b%closed = .true.

    rc = itb_blob512_new_c(b%handle)
    if (rc /= STATUS_OK) then
      b%handle = itb_null_handle
      b%closed = .true.
      call raise_itb_error(rc)
    end if
    b%closed = .false.
  end subroutine

  ! ----------------------------------------------------------------
  ! Lifecycle (per-width destroy / final)
  ! ----------------------------------------------------------------

  ! Releases the libitb handle via `ITB_Blob_Free` and marks the
  ! wrapper closed. Idempotent. Canonical lifecycle release for
  ! production code -- the `final ::` hook is a safety net only,
  ! its invocation timing is non-deterministic across compilers.
  subroutine itb_blob128_destroy(self)
    class(itb_blob128_t), intent(inout) :: self
    integer(itb_status_kind) :: rc

    if (self%closed) then
      self%handle = itb_null_handle
      return
    end if
    if (self%handle /= itb_null_handle) then
      rc = itb_blob_free_c(self%handle)
      if (rc /= STATUS_OK .and. rc /= STATUS_BAD_HANDLE) call raise_itb_error(rc)
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  subroutine itb_blob256_destroy(self)
    class(itb_blob256_t), intent(inout) :: self
    integer(itb_status_kind) :: rc

    if (self%closed) then
      self%handle = itb_null_handle
      return
    end if
    if (self%handle /= itb_null_handle) then
      rc = itb_blob_free_c(self%handle)
      if (rc /= STATUS_OK .and. rc /= STATUS_BAD_HANDLE) call raise_itb_error(rc)
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  subroutine itb_blob512_destroy(self)
    class(itb_blob512_t), intent(inout) :: self
    integer(itb_status_kind) :: rc

    if (self%closed) then
      self%handle = itb_null_handle
      return
    end if
    if (self%handle /= itb_null_handle) then
      rc = itb_blob_free_c(self%handle)
      if (rc /= STATUS_OK .and. rc /= STATUS_BAD_HANDLE) call raise_itb_error(rc)
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  ! Safety-net hooks -- non-deterministic across compilers. Errors
  ! are swallowed because the hook may fire at unpredictable program
  ! scopes (temporaries during reallocation, end-of-program-unit
  ! deferral, re-entry from another final).
  subroutine itb_blob128_final(self)
    type(itb_blob128_t), intent(inout) :: self
    if (self%closed) return
    if (self%handle /= itb_null_handle) then
      block
        integer(itb_status_kind) :: rc
        rc = itb_blob_free_c(self%handle)
      end block
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  subroutine itb_blob256_final(self)
    type(itb_blob256_t), intent(inout) :: self
    if (self%closed) return
    if (self%handle /= itb_null_handle) then
      block
        integer(itb_status_kind) :: rc
        rc = itb_blob_free_c(self%handle)
      end block
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  subroutine itb_blob512_final(self)
    type(itb_blob512_t), intent(inout) :: self
    if (self%closed) return
    if (self%handle /= itb_null_handle) then
      block
        integer(itb_status_kind) :: rc
        rc = itb_blob_free_c(self%handle)
      end block
    end if
    self%handle = itb_null_handle
    self%closed = .true.
  end subroutine

  ! ----------------------------------------------------------------
  ! Raw-handle / closed-state introspection (escape hatches)
  ! ----------------------------------------------------------------

  function itb_blob128_raw_handle(self) result(h)
    class(itb_blob128_t), intent(in) :: self
    integer(itb_handle_kind)         :: h
    h = self%handle
  end function

  function itb_blob256_raw_handle(self) result(h)
    class(itb_blob256_t), intent(in) :: self
    integer(itb_handle_kind)         :: h
    h = self%handle
  end function

  function itb_blob512_raw_handle(self) result(h)
    class(itb_blob512_t), intent(in) :: self
    integer(itb_handle_kind)         :: h
    h = self%handle
  end function

  function itb_blob128_is_closed(self) result(b)
    class(itb_blob128_t), intent(in) :: self
    logical                          :: b
    b = self%closed
  end function

  function itb_blob256_is_closed(self) result(b)
    class(itb_blob256_t), intent(in) :: self
    logical                          :: b
    b = self%closed
  end function

  function itb_blob512_is_closed(self) result(b)
    class(itb_blob512_t), intent(in) :: self
    logical                          :: b
    b = self%closed
  end function

  ! ----------------------------------------------------------------
  ! Inverted-signature getters: width / mode
  ! ----------------------------------------------------------------

  ! `ITB_Blob_Width` follows the convention "C return value carries
  ! the data, outStatus carries the libitb status code". Mirrors
  ! `itb_seed_width`'s shape.
  function itb_blob128_width(self) result(w)
    class(itb_blob128_t), intent(in) :: self
    integer(itb_int32_kind)          :: w
    integer(itb_status_kind) :: st
    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    w = itb_blob_width_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  function itb_blob256_width(self) result(w)
    class(itb_blob256_t), intent(in) :: self
    integer(itb_int32_kind)          :: w
    integer(itb_status_kind) :: st
    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    w = itb_blob_width_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  function itb_blob512_width(self) result(w)
    class(itb_blob512_t), intent(in) :: self
    integer(itb_int32_kind)          :: w
    integer(itb_status_kind) :: st
    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    w = itb_blob_width_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  ! `ITB_Blob_Mode` -- inverted-signature getter, returns the mode
  ! field (0 = unset, 1 = Single, 3 = Triple).
  function itb_blob128_mode(self) result(v)
    class(itb_blob128_t), intent(in) :: self
    integer(itb_int32_kind)          :: v
    integer(itb_status_kind) :: st
    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    v = itb_blob_mode_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  function itb_blob256_mode(self) result(v)
    class(itb_blob256_t), intent(in) :: self
    integer(itb_int32_kind)          :: v
    integer(itb_status_kind) :: st
    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    v = itb_blob_mode_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  function itb_blob512_mode(self) result(v)
    class(itb_blob512_t), intent(in) :: self
    integer(itb_int32_kind)          :: v
    integer(itb_status_kind) :: st
    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    v = itb_blob_mode_c(self%handle, st)
    if (st /= STATUS_OK) call raise_itb_error(st)
  end function

  ! ----------------------------------------------------------------
  ! Per-slot key setters / getters
  ! ----------------------------------------------------------------

  ! Stores raw hash key bytes at the given slot. 256 / 512 widths
  ! require exactly 32 / 64 bytes; 128 width accepts variable
  ! lengths (empty for siphash24, 16 bytes for aescmac). Pass an
  ! empty `key` array to clear a previously-set slot.
  subroutine itb_blob128_set_key(self, slot, key)
    class(itb_blob128_t),                       intent(inout) :: self
    integer,                                    intent(in)    :: slot
    integer(itb_byte_kind), target, contiguous, intent(in)    :: key(:)
    integer(itb_size_kind) :: key_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: key_ptr

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    key_len = int(size(key), itb_size_kind)
    key_ptr = c_null_ptr
    if (key_len > 0) key_ptr = c_loc(key)
    rc = itb_blob_set_key_c(self%handle, int(slot, c_int), key_ptr, key_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob256_set_key(self, slot, key)
    class(itb_blob256_t),                       intent(inout) :: self
    integer,                                    intent(in)    :: slot
    integer(itb_byte_kind), target, contiguous, intent(in)    :: key(:)
    integer(itb_size_kind) :: key_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: key_ptr

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    key_len = int(size(key), itb_size_kind)
    key_ptr = c_null_ptr
    if (key_len > 0) key_ptr = c_loc(key)
    rc = itb_blob_set_key_c(self%handle, int(slot, c_int), key_ptr, key_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob512_set_key(self, slot, key)
    class(itb_blob512_t),                       intent(inout) :: self
    integer,                                    intent(in)    :: slot
    integer(itb_byte_kind), target, contiguous, intent(in)    :: key(:)
    integer(itb_size_kind) :: key_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: key_ptr

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    key_len = int(size(key), itb_size_kind)
    key_ptr = c_null_ptr
    if (key_len > 0) key_ptr = c_loc(key)
    rc = itb_blob_set_key_c(self%handle, int(slot, c_int), key_ptr, key_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  ! Reads the raw hash key bytes from the given slot via two-call
  ! probe (first call with NULL output to discover required length,
  ! then allocate scratch and copy into the function's allocatable
  ! result). Empty result when the slot is unset.
  function itb_blob128_get_key(self, slot) result(key)
    class(itb_blob128_t), intent(in) :: self
    integer,              intent(in) :: slot
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer :: i

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_len = 0_itb_size_kind
    rc = itb_blob_get_key_c(self%handle, int(slot, c_int),     &
                              c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (key(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_get_key_c(self%handle, int(slot, c_int),     &
                              c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (key(int(out_len)))
    do i = 1, int(out_len)
      key(i) = scratch(i)
    end do
  end function

  function itb_blob256_get_key(self, slot) result(key)
    class(itb_blob256_t), intent(in) :: self
    integer,              intent(in) :: slot
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer :: i

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_len = 0_itb_size_kind
    rc = itb_blob_get_key_c(self%handle, int(slot, c_int),     &
                              c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (key(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_get_key_c(self%handle, int(slot, c_int),     &
                              c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (key(int(out_len)))
    do i = 1, int(out_len)
      key(i) = scratch(i)
    end do
  end function

  function itb_blob512_get_key(self, slot) result(key)
    class(itb_blob512_t), intent(in) :: self
    integer,              intent(in) :: slot
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer :: i

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_len = 0_itb_size_kind
    rc = itb_blob_get_key_c(self%handle, int(slot, c_int),     &
                              c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (key(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_get_key_c(self%handle, int(slot, c_int),     &
                              c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (key(int(out_len)))
    do i = 1, int(out_len)
      key(i) = scratch(i)
    end do
  end function

  ! ----------------------------------------------------------------
  ! Per-slot components setters / getters
  ! ----------------------------------------------------------------

  ! Stores the seed components (uint64 array) at the given slot.
  ! Component count must satisfy the 8..MaxKeyBits/64 multiple-of-8
  ! invariant; validation is deferred to export / import time, not
  ! enforced at the setter call.
  subroutine itb_blob128_set_components(self, slot, comps)
    class(itb_blob128_t),                  intent(inout) :: self
    integer,                               intent(in)    :: slot
    integer(itb_u64_kind), target, contiguous, intent(in) :: comps(:)
    integer(itb_size_kind) :: count
    integer(itb_status_kind) :: rc
    type(c_ptr) :: comp_ptr

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    count = int(size(comps), itb_size_kind)
    comp_ptr = c_null_ptr
    if (count > 0) comp_ptr = c_loc(comps)
    rc = itb_blob_set_components_c(self%handle, int(slot, c_int), comp_ptr, count)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob256_set_components(self, slot, comps)
    class(itb_blob256_t),                  intent(inout) :: self
    integer,                               intent(in)    :: slot
    integer(itb_u64_kind), target, contiguous, intent(in) :: comps(:)
    integer(itb_size_kind) :: count
    integer(itb_status_kind) :: rc
    type(c_ptr) :: comp_ptr

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    count = int(size(comps), itb_size_kind)
    comp_ptr = c_null_ptr
    if (count > 0) comp_ptr = c_loc(comps)
    rc = itb_blob_set_components_c(self%handle, int(slot, c_int), comp_ptr, count)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob512_set_components(self, slot, comps)
    class(itb_blob512_t),                  intent(inout) :: self
    integer,                               intent(in)    :: slot
    integer(itb_u64_kind), target, contiguous, intent(in) :: comps(:)
    integer(itb_size_kind) :: count
    integer(itb_status_kind) :: rc
    type(c_ptr) :: comp_ptr

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    count = int(size(comps), itb_size_kind)
    comp_ptr = c_null_ptr
    if (count > 0) comp_ptr = c_loc(comps)
    rc = itb_blob_set_components_c(self%handle, int(slot, c_int), comp_ptr, count)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  ! Reads the seed components (uint64 array) from the given slot via
  ! two-call probe -- the libitb-side `outCount` reports the number
  ! of uint64 elements (NOT bytes). Empty result when the slot is
  ! unset.
  function itb_blob128_get_components(self, slot) result(comps)
    class(itb_blob128_t), intent(in) :: self
    integer,              intent(in) :: slot
    integer(itb_u64_kind), allocatable :: comps(:)
    integer(itb_u64_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_count
    integer(itb_status_kind) :: rc
    integer :: i

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_count = 0_itb_size_kind
    rc = itb_blob_get_components_c(self%handle, int(slot, c_int),     &
                                     c_null_ptr, 0_itb_size_kind, out_count)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_count == 0) then
      allocate (comps(0))
      return
    end if
    cap = out_count
    allocate (scratch(cap))
    rc = itb_blob_get_components_c(self%handle, int(slot, c_int),     &
                                     c_loc(scratch), cap, out_count)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (comps(int(out_count)))
    do i = 1, int(out_count)
      comps(i) = scratch(i)
    end do
  end function

  function itb_blob256_get_components(self, slot) result(comps)
    class(itb_blob256_t), intent(in) :: self
    integer,              intent(in) :: slot
    integer(itb_u64_kind), allocatable :: comps(:)
    integer(itb_u64_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_count
    integer(itb_status_kind) :: rc
    integer :: i

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_count = 0_itb_size_kind
    rc = itb_blob_get_components_c(self%handle, int(slot, c_int),     &
                                     c_null_ptr, 0_itb_size_kind, out_count)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_count == 0) then
      allocate (comps(0))
      return
    end if
    cap = out_count
    allocate (scratch(cap))
    rc = itb_blob_get_components_c(self%handle, int(slot, c_int),     &
                                     c_loc(scratch), cap, out_count)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (comps(int(out_count)))
    do i = 1, int(out_count)
      comps(i) = scratch(i)
    end do
  end function

  function itb_blob512_get_components(self, slot) result(comps)
    class(itb_blob512_t), intent(in) :: self
    integer,              intent(in) :: slot
    integer(itb_u64_kind), allocatable :: comps(:)
    integer(itb_u64_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_count
    integer(itb_status_kind) :: rc
    integer :: i

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_count = 0_itb_size_kind
    rc = itb_blob_get_components_c(self%handle, int(slot, c_int),     &
                                     c_null_ptr, 0_itb_size_kind, out_count)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_count == 0) then
      allocate (comps(0))
      return
    end if
    cap = out_count
    allocate (scratch(cap))
    rc = itb_blob_get_components_c(self%handle, int(slot, c_int),     &
                                     c_loc(scratch), cap, out_count)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (comps(int(out_count)))
    do i = 1, int(out_count)
      comps(i) = scratch(i)
    end do
  end function

  ! ----------------------------------------------------------------
  ! MAC key setter / getter
  ! ----------------------------------------------------------------

  ! Stores the optional MAC key bytes on the handle. Pass an empty
  ! `key` array to clear a previously-set key.
  subroutine itb_blob128_set_mac_key(self, key)
    class(itb_blob128_t),                       intent(inout) :: self
    integer(itb_byte_kind), target, contiguous, intent(in)    :: key(:)
    integer(itb_size_kind) :: key_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: key_ptr

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    key_len = int(size(key), itb_size_kind)
    key_ptr = c_null_ptr
    if (key_len > 0) key_ptr = c_loc(key)
    rc = itb_blob_set_mac_key_c(self%handle, key_ptr, key_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob256_set_mac_key(self, key)
    class(itb_blob256_t),                       intent(inout) :: self
    integer(itb_byte_kind), target, contiguous, intent(in)    :: key(:)
    integer(itb_size_kind) :: key_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: key_ptr

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    key_len = int(size(key), itb_size_kind)
    key_ptr = c_null_ptr
    if (key_len > 0) key_ptr = c_loc(key)
    rc = itb_blob_set_mac_key_c(self%handle, key_ptr, key_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob512_set_mac_key(self, key)
    class(itb_blob512_t),                       intent(inout) :: self
    integer(itb_byte_kind), target, contiguous, intent(in)    :: key(:)
    integer(itb_size_kind) :: key_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: key_ptr

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    key_len = int(size(key), itb_size_kind)
    key_ptr = c_null_ptr
    if (key_len > 0) key_ptr = c_loc(key)
    rc = itb_blob_set_mac_key_c(self%handle, key_ptr, key_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  ! Reads the MAC key bytes via two-call probe. Empty result when no
  ! MAC key is associated with the handle.
  function itb_blob128_get_mac_key(self) result(key)
    class(itb_blob128_t), intent(in) :: self
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer :: i

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_len = 0_itb_size_kind
    rc = itb_blob_get_mac_key_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (key(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_get_mac_key_c(self%handle, c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (key(int(out_len)))
    do i = 1, int(out_len)
      key(i) = scratch(i)
    end do
  end function

  function itb_blob256_get_mac_key(self) result(key)
    class(itb_blob256_t), intent(in) :: self
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer :: i

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_len = 0_itb_size_kind
    rc = itb_blob_get_mac_key_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (key(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_get_mac_key_c(self%handle, c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (key(int(out_len)))
    do i = 1, int(out_len)
      key(i) = scratch(i)
    end do
  end function

  function itb_blob512_get_mac_key(self) result(key)
    class(itb_blob512_t), intent(in) :: self
    integer(itb_byte_kind), allocatable :: key(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer :: i

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_len = 0_itb_size_kind
    rc = itb_blob_get_mac_key_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (key(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_get_mac_key_c(self%handle, c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (key(int(out_len)))
    do i = 1, int(out_len)
      key(i) = scratch(i)
    end do
  end function

  ! ----------------------------------------------------------------
  ! MAC name setter / getter
  ! ----------------------------------------------------------------

  ! Stores the optional MAC name on the handle. Pass an empty
  ! Fortran string to clear a previously-set name -- the wrapper
  ! routes a zero-length name through libitb's "clear" path, matching
  ! the C binding's NULL-or-empty handling.
  subroutine itb_blob128_set_mac_name(self, name)
    class(itb_blob128_t), intent(inout) :: self
    character(*),         intent(in)    :: name
    character(kind=c_char), allocatable, target :: c_name(:)
    integer(itb_status_kind) :: rc
    integer(itb_size_kind) :: name_len
    type(c_ptr) :: name_ptr

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    name_len = int(len(name), itb_size_kind)
    if (name_len == 0) then
      name_ptr = c_null_ptr
    else
      call make_c_string(name, c_name)
      name_ptr = c_loc(c_name)
    end if
    rc = itb_blob_set_mac_name_c(self%handle, name_ptr, name_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob256_set_mac_name(self, name)
    class(itb_blob256_t), intent(inout) :: self
    character(*),         intent(in)    :: name
    character(kind=c_char), allocatable, target :: c_name(:)
    integer(itb_status_kind) :: rc
    integer(itb_size_kind) :: name_len
    type(c_ptr) :: name_ptr

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    name_len = int(len(name), itb_size_kind)
    if (name_len == 0) then
      name_ptr = c_null_ptr
    else
      call make_c_string(name, c_name)
      name_ptr = c_loc(c_name)
    end if
    rc = itb_blob_set_mac_name_c(self%handle, name_ptr, name_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob512_set_mac_name(self, name)
    class(itb_blob512_t), intent(inout) :: self
    character(*),         intent(in)    :: name
    character(kind=c_char), allocatable, target :: c_name(:)
    integer(itb_status_kind) :: rc
    integer(itb_size_kind) :: name_len
    type(c_ptr) :: name_ptr

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    name_len = int(len(name), itb_size_kind)
    if (name_len == 0) then
      name_ptr = c_null_ptr
    else
      call make_c_string(name, c_name)
      name_ptr = c_loc(c_name)
    end if
    rc = itb_blob_set_mac_name_c(self%handle, name_ptr, name_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  ! Reads the MAC name from the handle via two-call probe with
  ! NUL-strip applied to the result. Empty string when no MAC name
  ! is associated.
  function itb_blob128_get_mac_name(self) result(s)
    class(itb_blob128_t), intent(in) :: self
    character(:), allocatable :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_len = 0_itb_size_kind
    rc = itb_blob_get_mac_name_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    cap = max(out_len + 1_itb_size_kind, 64_itb_size_kind)
    allocate (buf(cap))
    rc = itb_blob_get_mac_name_c(self%handle, c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

  function itb_blob256_get_mac_name(self) result(s)
    class(itb_blob256_t), intent(in) :: self
    character(:), allocatable :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_len = 0_itb_size_kind
    rc = itb_blob_get_mac_name_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    cap = max(out_len + 1_itb_size_kind, 64_itb_size_kind)
    allocate (buf(cap))
    rc = itb_blob_get_mac_name_c(self%handle, c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

  function itb_blob512_get_mac_name(self) result(s)
    class(itb_blob512_t), intent(in) :: self
    character(:), allocatable :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)

    out_len = 0_itb_size_kind
    rc = itb_blob_get_mac_name_c(self%handle, c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    cap = max(out_len + 1_itb_size_kind, 64_itb_size_kind)
    allocate (buf(cap))
    rc = itb_blob_get_mac_name_c(self%handle, c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

  ! ----------------------------------------------------------------
  ! Export (Single + Triple)
  ! ----------------------------------------------------------------

  ! Serialises the Blob's Single-Ouroboros state into a JSON envelope
  ! via two-call probe. `opts` is a bitmask of the binding's
  ! ITB_BLOB_OPT_LOCKSEED / ITB_BLOB_OPT_MAC constants combined via
  ! `ior`; a default of 0 emits the base seed material only. The
  ! returned blob is a defensive copy owned by the caller's
  ! allocatable.
  function itb_blob128_export(self, opts) result(blob)
    class(itb_blob128_t),    intent(in) :: self
    integer,       optional, intent(in) :: opts
    integer(itb_byte_kind), allocatable :: blob(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer(c_int) :: opts_c
    integer :: i

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    opts_c = 0_c_int
    if (present(opts)) opts_c = int(opts, c_int)

    out_len = 0_itb_size_kind
    rc = itb_blob_export_c(self%handle, opts_c, &
                             c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (blob(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_export_c(self%handle, opts_c, &
                             c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (blob(int(out_len)))
    do i = 1, int(out_len)
      blob(i) = scratch(i)
    end do
  end function

  function itb_blob256_export(self, opts) result(blob)
    class(itb_blob256_t),    intent(in) :: self
    integer,       optional, intent(in) :: opts
    integer(itb_byte_kind), allocatable :: blob(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer(c_int) :: opts_c
    integer :: i

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    opts_c = 0_c_int
    if (present(opts)) opts_c = int(opts, c_int)

    out_len = 0_itb_size_kind
    rc = itb_blob_export_c(self%handle, opts_c, &
                             c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (blob(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_export_c(self%handle, opts_c, &
                             c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (blob(int(out_len)))
    do i = 1, int(out_len)
      blob(i) = scratch(i)
    end do
  end function

  function itb_blob512_export(self, opts) result(blob)
    class(itb_blob512_t),    intent(in) :: self
    integer,       optional, intent(in) :: opts
    integer(itb_byte_kind), allocatable :: blob(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer(c_int) :: opts_c
    integer :: i

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    opts_c = 0_c_int
    if (present(opts)) opts_c = int(opts, c_int)

    out_len = 0_itb_size_kind
    rc = itb_blob_export_c(self%handle, opts_c, &
                             c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (blob(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_export_c(self%handle, opts_c, &
                             c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (blob(int(out_len)))
    do i = 1, int(out_len)
      blob(i) = scratch(i)
    end do
  end function

  ! Triple-Ouroboros export counterpart -- mirrors `export` but
  ! routes through `ITB_Blob_Export3` to pack the seven-seed
  ! Triple state.
  function itb_blob128_export_3(self, opts) result(blob)
    class(itb_blob128_t),    intent(in) :: self
    integer,       optional, intent(in) :: opts
    integer(itb_byte_kind), allocatable :: blob(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer(c_int) :: opts_c
    integer :: i

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    opts_c = 0_c_int
    if (present(opts)) opts_c = int(opts, c_int)

    out_len = 0_itb_size_kind
    rc = itb_blob_export3_c(self%handle, opts_c, &
                              c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (blob(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_export3_c(self%handle, opts_c, &
                              c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (blob(int(out_len)))
    do i = 1, int(out_len)
      blob(i) = scratch(i)
    end do
  end function

  function itb_blob256_export_3(self, opts) result(blob)
    class(itb_blob256_t),    intent(in) :: self
    integer,       optional, intent(in) :: opts
    integer(itb_byte_kind), allocatable :: blob(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer(c_int) :: opts_c
    integer :: i

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    opts_c = 0_c_int
    if (present(opts)) opts_c = int(opts, c_int)

    out_len = 0_itb_size_kind
    rc = itb_blob_export3_c(self%handle, opts_c, &
                              c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (blob(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_export3_c(self%handle, opts_c, &
                              c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (blob(int(out_len)))
    do i = 1, int(out_len)
      blob(i) = scratch(i)
    end do
  end function

  function itb_blob512_export_3(self, opts) result(blob)
    class(itb_blob512_t),    intent(in) :: self
    integer,       optional, intent(in) :: opts
    integer(itb_byte_kind), allocatable :: blob(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc
    integer(c_int) :: opts_c
    integer :: i

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    opts_c = 0_c_int
    if (present(opts)) opts_c = int(opts, c_int)

    out_len = 0_itb_size_kind
    rc = itb_blob_export3_c(self%handle, opts_c, &
                              c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    if (out_len == 0) then
      allocate (blob(0))
      return
    end if
    cap = out_len
    allocate (scratch(cap))
    rc = itb_blob_export3_c(self%handle, opts_c, &
                              c_loc(scratch), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    allocate (blob(int(out_len)))
    do i = 1, int(out_len)
      blob(i) = scratch(i)
    end do
  end function

  ! ----------------------------------------------------------------
  ! Import (Single + Triple)
  ! ----------------------------------------------------------------

  ! Parses a Single-Ouroboros JSON blob, populates the handle's
  ! slots, and applies the captured globals via the process-wide
  ! setters. Returns
  ! `STATUS_BLOB_MODE_MISMATCH` on a Triple-mode blob,
  ! `STATUS_BLOB_MALFORMED` on parse / shape failure,
  ! `STATUS_BLOB_VERSION_TOO_NEW` on a version field higher than
  ! this build supports.
  subroutine itb_blob128_import(self, blob)
    class(itb_blob128_t),                       intent(inout) :: self
    integer(itb_byte_kind), target, contiguous, intent(in)    :: blob(:)
    integer(itb_size_kind) :: blob_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: blob_ptr

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    blob_len = int(size(blob), itb_size_kind)
    blob_ptr = c_null_ptr
    if (blob_len > 0) blob_ptr = c_loc(blob)
    rc = itb_blob_import_c(self%handle, blob_ptr, blob_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob256_import(self, blob)
    class(itb_blob256_t),                       intent(inout) :: self
    integer(itb_byte_kind), target, contiguous, intent(in)    :: blob(:)
    integer(itb_size_kind) :: blob_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: blob_ptr

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    blob_len = int(size(blob), itb_size_kind)
    blob_ptr = c_null_ptr
    if (blob_len > 0) blob_ptr = c_loc(blob)
    rc = itb_blob_import_c(self%handle, blob_ptr, blob_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob512_import(self, blob)
    class(itb_blob512_t),                       intent(inout) :: self
    integer(itb_byte_kind), target, contiguous, intent(in)    :: blob(:)
    integer(itb_size_kind) :: blob_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: blob_ptr

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    blob_len = int(size(blob), itb_size_kind)
    blob_ptr = c_null_ptr
    if (blob_len > 0) blob_ptr = c_loc(blob)
    rc = itb_blob_import_c(self%handle, blob_ptr, blob_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  ! Triple-Ouroboros import counterpart -- routes through
  ! `ITB_Blob_Import3`. A Single-mode wire blob fed here surfaces
  ! as `STATUS_BLOB_MODE_MISMATCH`.
  subroutine itb_blob128_import_3(self, blob)
    class(itb_blob128_t),                       intent(inout) :: self
    integer(itb_byte_kind), target, contiguous, intent(in)    :: blob(:)
    integer(itb_size_kind) :: blob_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: blob_ptr

    if (blob128_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    blob_len = int(size(blob), itb_size_kind)
    blob_ptr = c_null_ptr
    if (blob_len > 0) blob_ptr = c_loc(blob)
    rc = itb_blob_import3_c(self%handle, blob_ptr, blob_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob256_import_3(self, blob)
    class(itb_blob256_t),                       intent(inout) :: self
    integer(itb_byte_kind), target, contiguous, intent(in)    :: blob(:)
    integer(itb_size_kind) :: blob_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: blob_ptr

    if (blob256_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    blob_len = int(size(blob), itb_size_kind)
    blob_ptr = c_null_ptr
    if (blob_len > 0) blob_ptr = c_loc(blob)
    rc = itb_blob_import3_c(self%handle, blob_ptr, blob_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  subroutine itb_blob512_import_3(self, blob)
    class(itb_blob512_t),                       intent(inout) :: self
    integer(itb_byte_kind), target, contiguous, intent(in)    :: blob(:)
    integer(itb_size_kind) :: blob_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: blob_ptr

    if (blob512_is_closed_state(self)) call raise_itb_error(STATUS_BAD_HANDLE)
    blob_len = int(size(blob), itb_size_kind)
    blob_ptr = c_null_ptr
    if (blob_len > 0) blob_ptr = c_loc(blob)
    rc = itb_blob_import3_c(self%handle, blob_ptr, blob_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

end module itb_blob
