! itb_strings.f90 -- C-string <-> Fortran-string helpers.
!
! Every libitb FFI string boundary uses one of two conventions:
!
!   * INPUT (Fortran -> libitb): NUL-terminated C string. The caller
!     allocates a `character(kind=c_char), target :: buf(:)` with one
!     extra byte, copies the Fortran source character-by-character,
!     appends `c_null_char`, and passes `c_loc(buf)` to the FFI.
!     `make_c_string` is the canonical helper for this path.
!
!   * OUTPUT (libitb -> Fortran): libitb writes the visible bytes
!     followed by a single NUL terminator and reports `out_len` set
!     to the FULL byte count INCLUDING the NUL (i.e. `strlen + 1`).
!     The Fortran wrapper must STRIP the trailing NUL when copying
!     into the result string. `c_buffer_to_fortran_string` is the
!     canonical helper for this path.
!
! Both helpers are tiny (~10-line bodies) but every wrapper around a
! libitb string getter must use them; ad-hoc reimplementations have
! been a recurring source of off-by-one and double-NUL bugs in past
! ITB bindings, and the contract is uniform across every language
! port.
!
! The "two-call probe" pattern (call once with `cap=0` to discover
! the needed length, allocate, call again) is left to each higher-
! level wrapper because the surface differs per getter family
! (handle + slot, handle alone, no handle, etc.); centralising it
! here would require an abstract-interface zoo that adds more code
! than the duplication it removes.

module itb_strings
  use itb_kinds
  implicit none
  private

  public :: c_buffer_to_fortran_string
  public :: make_c_string
  public :: fortran_string_to_c_buffer

contains

  ! Convert a libitb-output `(buf, len)` pair to a Fortran allocatable
  ! string with the trailing NUL byte stripped. `c_buf(1:c_len)` may
  ! end with a NUL (it does in the libitb getter convention) -- if it
  ! does, the NUL is removed; if it does not, all c_len bytes pass
  ! through. The output is allocated to the visible length only.
  !
  ! `c_buf` is declared as the assumed-size `(*)` array because most
  ! callers receive it via `c_f_pointer` from a `type(c_ptr)`, or pass
  ! a fixed-size local buffer of unknown declared length; assumed-size
  ! defers the bounds check to the caller's discipline.
  subroutine c_buffer_to_fortran_string(c_buf, c_len, out)
    character(kind=c_char), intent(in)         :: c_buf(*)
    integer(itb_size_kind),  intent(in)        :: c_len
    character(:), allocatable, intent(out)     :: out
    integer :: visible, i

    visible = int(c_len)
    if (visible < 0) visible = 0
    if (visible > 0) then
      ! Strip a single trailing NUL if present.
      if (c_buf(visible) == c_null_char) visible = visible - 1
    end if

    allocate (character(len=visible) :: out)
    do i = 1, visible
      out(i:i) = c_buf(i)
    end do
  end subroutine

  ! Build a NUL-terminated `c_char` array from a Fortran character
  ! source. Output `c_buf` is allocated to `len(s) + 1` bytes; bytes
  ! `1..len(s)` carry the source characters, byte `len(s)+1` is
  ! `c_null_char`. The caller passes `c_loc(c_buf)` to the FFI.
  !
  ! Empty Fortran strings are mapped to a one-byte buffer holding only
  ! the terminator. This keeps `c_loc(c_buf)` valid and avoids the
  ! NULL-pointer footgun (libitb's "default MAC" override at the
  ! binding boundary intentionally treats empty / NULL macName the
  ! same way -- both surface as the implicit `hmac-blake3` default).
  subroutine make_c_string(s, c_buf)
    character(*), intent(in)                                   :: s
    character(kind=c_char), allocatable, target, intent(out)   :: c_buf(:)
    integer :: i, n

    n = len(s)
    allocate (c_buf(n + 1))
    do i = 1, n
      c_buf(i) = s(i:i)
    end do
    c_buf(n + 1) = c_null_char
  end subroutine

  ! Compatibility alias kept for symmetry with `c_buffer_to_fortran_string`.
  ! Implementations may evolve; existing call sites should use this
  ! rather than `make_c_string` when reading more naturally as
  ! "Fortran string -> C buffer".
  subroutine fortran_string_to_c_buffer(s, c_buf)
    character(*), intent(in)                                   :: s
    character(kind=c_char), allocatable, target, intent(out)   :: c_buf(:)
    call make_c_string(s, c_buf)
  end subroutine

end module itb_strings
