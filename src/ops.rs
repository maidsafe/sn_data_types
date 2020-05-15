
#[derive(Debug, Clone)]
pub struct Packet<Op> {
    pub src: Identity,
    pub dst: Identity,
    pub payload: Payload<Op>,
    pub sig: Sig,
}

#[derive(Debug, Clone, Serialize)]
pub enum Payload<Op> {
    RequestValidation {
        msg: Msg<Op>,
    },
    #[allow(unused)]
    SignedValidated {
        msg: Msg<Op>,
        sig: Sig,
    },
    #[allow(unused)]
    ProofOfAgreement {
        msg: Msg<Op>,
        proof: HashMap<Identity, Sig>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct Msg<Op> {
    op: BFTOp<Op>,
    dot: Dot<Identity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
enum BFTOp<Op> {
    #[allow(unused)]
    NewPeer(Identity),
    // TODO: support peers leaving
    AlgoOp(Op),
}
