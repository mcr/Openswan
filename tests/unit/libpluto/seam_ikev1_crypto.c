stf_status start_dh_secret(struct pluto_crypto_req_cont *cn
			   , struct state *st
			   , enum crypto_importance importance
			   , enum phase1_role init
			   , u_int16_t oakley_group2)
{
    struct pluto_crypto_req r;
    struct pcr_skeyid_q *dhq;
    err_t e;
    bool toomuch = FALSE;

    continuation = cn;
    pcr_init(&r, pcr_compute_dh, importance);
    return STF_SUSPEND;
}

