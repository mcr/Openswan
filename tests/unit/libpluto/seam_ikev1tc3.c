/* this is replicated in the unit test cases since the patching up of the crypto values is case specific */
void recv_pcap_packet(u_char *user
		      , const struct pcap_pkthdr *h
		      , const u_char *bytes)
{
    struct state *st;
    struct pcr_kenonce *kn = &crypto_req->pcr_d.kn;

    recv_pcap_packet_gen(user, h, bytes);

    /* find st involved */
    st = state_with_serialno(1);
    if(st != NULL) {
        passert(st != NULL);
        st->st_connection->extra_debugging = DBG_EMITTING|DBG_CONTROL|DBG_CONTROLMORE|DBG_CRYPT|DBG_PRIVATE;
        st->hidden_variables.st_nat_traversal |= NAT_T_WITH_NATD;

        clonetowirechunk(&kn->thespace, kn->space, &kn->n,   tc3_ni, tc3_ni_len);
        clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  tc3_gi, tc3_gi_len);
        clonetowirechunk(&kn->thespace, kn->space, &kn->secret, tc3_secret,tc3_secret_len);
    }

    run_continuation(crypto_req);
}
