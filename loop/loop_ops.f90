! The maintenance operations that mutate a live Pipeline handle
! between iterations: master rotation (--rekey-every) and blob reopen
! (--blob-cycle-every).

module loop_ops
  use, intrinsic :: iso_c_binding
  use itb3
  use loop_size, only: itoa
  use loop_state
  use loop_payload, only: fill_random
  implicit none
  private

  public :: worker_maintenance

  ! Byte length of each fresh master drawn for a rotation. Matches
  ! the size Init auto-generates for both the parallax and the
  ! wrapper master.
  integer, parameter :: REKEY_MASTER_SIZE = 32

contains

  ! Master rotation. Rotates the parallax + wrapper masters on every
  ! active Pipeline under the write lock and retains the refreshed
  ! blob for subsequent blob reopens. Masters are drawn fresh from
  ! the OS CSPRNG on every rotation regardless of --seed (master
  ! rotation is pipeline keying, not plaintext content); a disabled
  ! layer passes no bytes, which Rekey ignores. The eight inner seeds
  ! and the MAC key are untouched by design -- Rekey targets only the
  ! two outer-layer master secrets.
  function rekey_pipes(w, iter) result(ok)
    type(worker_t), intent(inout)  :: w
    integer(c_int64_t), intent(in) :: iter
    logical                        :: ok
    integer(c_int8_t), allocatable :: perm(:), wrap(:)
    integer(c_int8_t), allocatable :: rotated(:)
    type(itb_error_t) :: err

    ok = .false.
    if (cfg%parallax) then
      allocate (perm(REKEY_MASTER_SIZE))
      if (.not. fill_random(perm)) then
        call worker_fail(w, worker_tag(w%id, iter)//": csprng: parallax master")
        return
      end if
    else
      allocate (perm(0))
    end if
    if (cfg%wrapper) then
      allocate (wrap(REKEY_MASTER_SIZE))
      if (.not. fill_random(wrap)) then
        call worker_fail(w, worker_tag(w%id, iter)//": csprng: wrapper master")
        return
      end if
    else
      allocate (wrap(0))
    end if

    call wr_lock()
    if (stream_active) then
      call itb_pipeline_rekey(stream_pipe, perm, wrap, err, blob=rotated)
      if (.not. itb_ok(err)) then
        call worker_fail(w, worker_tag(w%id, iter)//": Rekey("// &
                         stream_profile//"): "//itb_error_text(err))
        call wr_unlock()
        return
      end if
      call move_alloc(rotated, stream_blob)
    end if
    if (msg_active) then
      call itb_pipeline_rekey(msg_pipe, perm, wrap, err, blob=rotated)
      if (.not. itb_ok(err)) then
        call worker_fail(w, worker_tag(w%id, iter)//": Rekey("// &
                         msg_profile//"): "//itb_error_text(err))
        call wr_unlock()
        return
      end if
      call move_alloc(rotated, msg_blob)
    end if
    rekeys = rekeys + 1_c_int64_t
    call log_line("rekey: "//worker_tag(w%id, iter)// &
                  " rotated parallax + wrapper masters (rekey #"// &
                  itoa(rekeys)//")")
    call wr_unlock()
    ok = .true.
  end function

  ! Blob reopen. Reopens every active Pipeline from its retained blob
  ! under the write lock: a fresh handle is loaded from the blob, the
  ! running handle is freed, and the fresh one is swapped in, so
  ! every later iteration round-trips through seeds and masters that
  ! survived a blob crossing. The input is the blob Init or the
  ! latest Rekey handed out, not a fresh Save: that is what a
  ! receiver holds, and reopening from it proves the handed-out bytes
  ! rather than the live state. The blob carries the Pipeline's full
  ! shape, so no override reaches the reopen. On a Load failure the
  ! running handle stays and the failure aborts the run.
  function blob_cycle_pipes(w, iter) result(ok)
    type(worker_t), intent(inout)  :: w
    integer(c_int64_t), intent(in) :: iter
    logical                        :: ok
    type(itb_pipeline_t) :: fresh
    type(itb_error_t)    :: err

    ok = .false.
    call wr_lock()
    if (stream_active) then
      call itb_pipeline_load(fresh, stream_blob, err)
      if (.not. itb_ok(err)) then
        call worker_fail(w, worker_tag(w%id, iter)//": Load("// &
                         stream_profile//"): "//itb_error_text(err))
        call wr_unlock()
        return
      end if
      call itb_pipeline_free(stream_pipe)
      stream_pipe = fresh
    end if
    if (msg_active) then
      call itb_pipeline_load(fresh, msg_blob, err)
      if (.not. itb_ok(err)) then
        call worker_fail(w, worker_tag(w%id, iter)//": Load("// &
                         msg_profile//"): "//itb_error_text(err))
        call wr_unlock()
        return
      end if
      call itb_pipeline_free(msg_pipe)
      msg_pipe = fresh
    end if
    blob_cycles = blob_cycles + 1_c_int64_t
    call log_line("blob-cycle: "//worker_tag(w%id, iter)// &
                  " reopened from session blob (cycle #"// &
                  itoa(blob_cycles)//")")
    call wr_unlock()
    ok = .true.
  end function

  ! Handle mutation. Runs the periodic Pipeline-mutating operations
  ! after a completed iteration: master rotation (--rekey-every) and
  ! blob reopen (--blob-cycle-every). Both intervals count per-worker
  ! iterations; the warmup iteration (iter 0) never triggers because
  ! the worker loop calls this for iter >= 1 only. Rekey rewrites the
  ! outer-layer keying of a live handle and a blob reopen replaces
  ! the handle outright; each takes the write lock, so in-flight
  ! cipher calls on other workers drain before anything changes and
  ! no encrypt is separated from its decrypt by either.
  function worker_maintenance(w, iter) result(ok)
    type(worker_t), intent(inout)  :: w
    integer(c_int64_t), intent(in) :: iter
    logical                        :: ok

    ok = .true.
    if (cfg%rekey_every > 0_c_int64_t) then
      if (mod(iter, cfg%rekey_every) == 0_c_int64_t) then
        ok = rekey_pipes(w, iter)
        if (.not. ok) return
      end if
    end if
    if (cfg%blob_cycle_every > 0_c_int64_t) then
      if (mod(iter, cfg%blob_cycle_every) == 0_c_int64_t) then
        ok = blob_cycle_pipes(w, iter)
      end if
    end if
  end function

end module loop_ops
