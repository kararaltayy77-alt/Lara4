#ifndef _LIBPROC_H_
  #define _LIBPROC_H_

  #include <sys/types.h>
  #include <stdint.h>

  #ifdef __cplusplus
  extern "C" {
  #endif

  #define PROC_PIDLISTFDS           1
  #define PROC_PIDTASKALLINFO       2
  #define PROC_PIDTBSDINFO          3
  #define PROC_PIDTASKINFO          4
  #define PROC_PIDTHREADINFO        5
  #define PROC_PIDLISTTHREADS       6
  #define PROC_PIDREGIONINFO        7
  #define PROC_PIDREGIONPATHINFO    8
  #define PROC_PIDVNODEPATHINFO     9
  #define PROC_PIDTHREADPATHINFO    10
  #define PROC_PIDPATHINFO          11

  #define PROX_FDTYPE_ATALK       ((uint32_t)0)
  #define PROX_FDTYPE_VNODE       ((uint32_t)1)
  #define PROX_FDTYPE_SOCKET      ((uint32_t)2)
  #define PROX_FDTYPE_PSHM        ((uint32_t)3)
  #define PROX_FDTYPE_PSEM        ((uint32_t)4)
  #define PROX_FDTYPE_KQUEUE      ((uint32_t)5)
  #define PROX_FDTYPE_PIPE        ((uint32_t)6)
  #define PROX_FDTYPE_FSEVENTS    ((uint32_t)7)
  #define PROX_FDTYPE_NETPOLICY   ((uint32_t)9)
  #define PROX_FDTYPE_MACH_MSG    ((uint32_t)10)

  struct proc_fdinfo {
      int32_t  proc_fd;
      uint32_t proc_fdtype;
  };

  struct proc_bsdinfo {
      uint32_t pbi_flags;
      uint32_t pbi_status;
      uint32_t pbi_xstatus;
      uint32_t pbi_pid;
      uint32_t pbi_ppid;
      uid_t    pbi_uid;
      gid_t    pbi_gid;
      uid_t    pbi_ruid;
      gid_t    pbi_rgid;
      uid_t    pbi_svuid;
      gid_t    pbi_svgid;
      uint32_t rfu_1;
      char     pbi_comm[16];
      char     pbi_name[32];
      uint32_t pbi_nfiles;
      uint32_t pbi_pgid;
      uint32_t pbi_pjobc;
      uint32_t e_tdev;
      uint32_t e_tpgid;
      int32_t  pbi_nice;
      uint64_t pbi_start_tvsec;
      uint64_t pbi_start_tvusec;
  };

  struct proc_taskinfo {
      uint64_t pti_virtual_size;
      uint64_t pti_resident_size;
      uint64_t pti_total_user;
      uint64_t pti_total_system;
      uint64_t pti_threads_user;
      uint64_t pti_threads_system;
      int32_t  pti_policy;
      int32_t  pti_faults;
      int32_t  pti_pageins;
      int32_t  pti_cow_faults;
      int32_t  pti_messages_sent;
      int32_t  pti_messages_received;
      int32_t  pti_syscalls_mach;
      int32_t  pti_syscalls_unix;
      int32_t  pti_csw;
      int32_t  pti_threadnum;
      int32_t  pti_numrunning;
      int32_t  pti_priority;
      uint64_t pti_phys_footprint;
  };

  struct proc_threadinfo {
      uint64_t pth_user_time;
      uint64_t pth_system_time;
      int32_t  pth_cpu_usage;
      int32_t  pth_policy;
      int32_t  pth_run_state;
      int32_t  pth_flags;
      int32_t  pth_sleep_time;
      int32_t  pth_curpri;
      int32_t  pth_priority;
      int32_t  pth_maxpriority;
      char     pth_name[64];
      uint64_t pth_thread_id;
  };

  #ifndef MAXPATHLEN
  #define MAXPATHLEN ((size_t)1024)
  #endif

  struct proc_regioninfo {
      int32_t  pri_protection;   /* vm_prot_t */
      uint32_t pri_max_protection;
      uint32_t pri_inheritance;
      uint32_t pri_flags;
      uint64_t pri_offset;
      uint32_t pri_behavior;
      uint32_t pri_user_wired_count;
      uint32_t pri_user_tag;
      uint32_t pri_pages_resident;
      uint32_t pri_pages_shared_now_private;
      uint32_t pri_pages_swapped_out;
      uint32_t pri_pages_dirtied;
      uint32_t pri_ref_count;
      uint32_t pri_shadow_depth;
      uint32_t pri_share_mode;
      uint32_t pri_private_pages_resident;
      uint32_t pri_shared_pages_resident;
      uint32_t pri_obj_id;
      uint32_t pri_depth;
      uint64_t pri_address;
      uint64_t pri_size;
  };

  struct vnode_info {
      uint8_t vi_stat[144];
      int     vi_type;
      int     vi_pad;
      uint8_t vi_fsid[8];
  };

  struct vnode_info_path {
      struct vnode_info vip_vi;
      char              vip_path[MAXPATHLEN];
  };

  struct proc_regionwithpathinfo {
      struct proc_regioninfo prp_prinfo;
      struct vnode_info_path prp_vip;
  };

  int  proc_listallpids(void *buffer, int buffersize);
  int  proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
  int  proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
  int  proc_name(int pid, void *buffer, uint32_t buffersize);
  int  proc_pidpath(int pid, void *buffer, uint32_t buffersize);

  #ifdef __cplusplus
  }
  #endif

  #endif /* _LIBPROC_H_ */
  