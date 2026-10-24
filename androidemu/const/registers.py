
# ID : (Op0, Op1, CRn, CRm, Op2)
ARM64_CNTVCT_EL0        =      (3, 3, 14, 0, 2)
ARM64_CNTFRQ_EL0        =      (3, 3, 14, 0, 0)
ARM64_CNTKCTL_EL1       =      (3, 0, 14, 1, 0)
ARM64_ID_AA64PFR0_EL1   =      (3, 0, 0, 4, 0)

# ID : (is_64bit_reg, coproc, opc1, opc2, CRn, CRm)
ARM32_CNTVCT            =      (True,  15, 1, 0, 0, 14), # CNTVCT (MRRC)
ARM32_CNTFRQ            =      (False, 15, 0, 0, 14, 0), # CNTFRQ (MRC)
ARM32_CNTKCTL           =      (False, 15, 0, 0, 14, 1), # CNTKCTL (MRC)