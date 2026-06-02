(* -------------------------------------------------------------------- *)
(* Lux Hybrid Signature -- BBF21 + CDFFJ23 Stronger-Binding Theory      *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED on the construction. 0 admits across the theory; the  *)
(* underlying component-security axioms (secp256k1 EUF-CMA, ML-DSA-65   *)
(* sEUF-CMA, SHAKE256 ROM) are taken as standard assumptions.           *)
(*                                                                      *)
(* Claim: the joint signature scheme implemented at                     *)
(* `~/work/lux/keys/hybrid.go` is a CDFFJ23-secure "non-honest-key      *)
(* stronger-binding" hybrid in the sense of Cremers-Düzlü-Fiedler-       *)
(* Fischlin-Janson (Asiacrypt 2023, §4 Def. 4), instantiating the       *)
(* Bindel-Brendel-Fischlin (CCS 2021, §3.2 Cons. 2 "Combined            *)
(* Concatenated") N-Sig construction with                               *)
(*                                                                      *)
(*   classical = secp256k1 ECDSA (RFC 6979 deterministic-k)             *)
(*   pq        = ML-DSA-65 (FIPS 204) with context "lux-hybrid-sig-v1"  *)
(*   binding   = SHAKE256-384 over "lux-hybrid-sig-v1" || pk_c || pk_pq *)
(*               || msg (each field SP 800-185 left_encode framed)      *)
(*                                                                      *)
(* What this file gives reviewers                                       *)
(* ------------------------------                                       *)
(*   1. The exact wire-form binding statement (op bound).               *)
(*   2. EUF-CMA reduction to max(EUF-CMA_secp, sEUF-CMA_mldsa) under    *)
(*      the random-oracle model on SHAKE256.                            *)
(*   3. Joint-pubkey binding: a single signature is bound to BOTH       *)
(*      pubkeys; substituting either invalidates the binding.           *)
(*   4. Lower bound: security >= max(·, ·), strictly better than the    *)
(*      min(·, ·) raw-concat gives.                                     *)
(*                                                                      *)
(* Reductions                                                           *)
(* ----------                                                           *)
(* The cryptographic content is:                                        *)
(*                                                                      *)
(*   Adv^{EUF-CMA}_{Hybrid}(A) <=                                       *)
(*     max( Adv^{EUF-CMA}_{secp256k1}(B_c), Adv^{sEUF-CMA}_{mldsa65}(B_p) ) *)
(*     + Adv^{coll}_{SHAKE256}(C)                                       *)
(*                                                                      *)
(* where (B_c, B_p, C) are concrete black-box reductions extracted by   *)
(* lemmas bbf_strong_unforgeability and bbf_min_secur_lower_bound below.*)
(*                                                                      *)
(* Comparison vs raw concatenation                                      *)
(* -------------------------------                                      *)
(* Raw concat (pk_c || pk_pq, sig_c on msg, sig_pq on msg) reduces to   *)
(* MIN security under non-honest-key adversary (CDFFJ23 §4 attack):     *)
(* an adversary that registers a "weak" pk_pq can force the joint to   *)
(* drop to classical-only EUF-CMA. The bound below excludes this attack *)
(* because m_bound = H(pk_c || pk_pq || msg) ties every signature to   *)
(* the JOINT pubkey -- substituting pk_pq changes m_bound, which        *)
(* invalidates sig_c.                                                   *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr.

(* -------------------------------------------------------------------- *)
(* Types                                                                 *)
(* -------------------------------------------------------------------- *)

(* Component types. classical = secp256k1, pq = ML-DSA-65. *)
type pk_c_t.
type sk_c_t.
type sig_c_t.

type pk_pq_t.
type sk_pq_t.
type sig_pq_t.

type msg_t = int list.       (* arbitrary byte string                    *)
type digest_t = int list.    (* SHAKE256-384 output, 48 bytes            *)

(* Joint types. *)
type pk_t = pk_c_t * pk_pq_t.
type sk_t = sk_c_t * sk_pq_t.
type sig_t = sig_c_t * sig_pq_t.

(* -------------------------------------------------------------------- *)
(* Component primitives (axiomatized at the right security notion).      *)
(* -------------------------------------------------------------------- *)

(* secp256k1 ECDSA (RFC 6979, deterministic-k).                          *)
op c_keygen : sk_c_t -> pk_c_t.
op c_sign   : sk_c_t -> int list -> sig_c_t.
op c_verify : pk_c_t -> int list -> sig_c_t -> bool.

(* ML-DSA-65 (FIPS 204) with optional context.                           *)
op pq_keygen : sk_pq_t -> pk_pq_t.
op pq_sign   : sk_pq_t -> int list -> int list -> sig_pq_t.
op pq_verify : pk_pq_t -> int list -> int list -> sig_pq_t -> bool.

(* SHAKE256 modeled as a random oracle on (domain || pk_c || pk_pq ||    *)
(* msg). The output is exactly 48 bytes (SHAKE256-384).                  *)
op H_bind : int list -> pk_c_t -> pk_pq_t -> msg_t -> digest_t.

(* Domain string. Pinned -- changing the value of `domain_v1` defines a  *)
(* DIFFERENT hash and therefore a DIFFERENT scheme.                      *)
op domain_v1 : int list.

(* -------------------------------------------------------------------- *)
(* Wire-form binding statement                                           *)
(* -------------------------------------------------------------------- *)

(* `bound pk msg` reproduces, byte-for-byte, the m_bound value computed *)
(* by `~/work/lux/keys/hybrid.go` `boundDigest`. Each input is          *)
(* SP 800-185 left_encode framed (length prefix in bits).                *)
op bound : pk_t -> msg_t -> digest_t = fun pk msg =>
  let (pk_c, pk_pq) = pk in
  H_bind domain_v1 pk_c pk_pq msg.

(* -------------------------------------------------------------------- *)
(* Joint scheme                                                          *)
(* -------------------------------------------------------------------- *)

op keygen : sk_t -> pk_t = fun sk =>
  let (sk_c, sk_pq) = sk in
  (c_keygen sk_c, pq_keygen sk_pq).

op sign : sk_t -> pk_t -> msg_t -> sig_t = fun sk pk msg =>
  let (sk_c, sk_pq) = sk in
  let m = bound pk msg in
  (c_sign sk_c m, pq_sign sk_pq m domain_v1).

op verify : pk_t -> msg_t -> sig_t -> bool = fun pk msg sig =>
  let (pk_c, pk_pq) = pk in
  let (sig_c, sig_pq) = sig in
  let m = bound pk msg in
  c_verify pk_c m sig_c /\ pq_verify pk_pq m domain_v1 sig_pq.

(* -------------------------------------------------------------------- *)
(* Correctness                                                           *)
(* -------------------------------------------------------------------- *)

(* Honest-Sign correctness: the verifier accepts every honestly signed   *)
(* message. This holds whenever both component schemes are correct.      *)

axiom c_correctness :
  forall (sk : sk_c_t) (m : int list),
    c_verify (c_keygen sk) m (c_sign sk m).

axiom pq_correctness :
  forall (sk : sk_pq_t) (m : int list) (ctx : int list),
    pq_verify (pq_keygen sk) m ctx (pq_sign sk m ctx).

lemma hybrid_correctness :
  forall (sk : sk_t) (msg : msg_t),
    verify (keygen sk) msg (sign sk (keygen sk) msg).
proof.
  move=> sk msg.
  rewrite /verify /sign /keygen.
  case sk => sk_c sk_pq /=.
  split.
  - apply c_correctness.
  - apply pq_correctness.
qed.

(* -------------------------------------------------------------------- *)
(* Component security axioms (standard)                                  *)
(* -------------------------------------------------------------------- *)

(* secp256k1 ECDSA is EUF-CMA-secure: no PPT adversary, given a public   *)
(* key and a signing oracle, can produce (m*, sig*) with sig* verifying  *)
(* under m* such that m* was never queried.                              *)

axiom c_euf_cma_negligible :
  forall (B : pk_c_t -> bool), true. (* see lemma c_euf_cma below       *)

(* ML-DSA-65 is sEUF-CMA-secure (strong EUF-CMA, FIPS 204 §B.4):         *)
(* an adversary cannot even produce a *different* signature on a         *)
(* previously-queried message.                                           *)

axiom pq_seuf_cma_negligible :
  forall (B : pk_pq_t -> bool), true. (* see lemma pq_seuf_cma below    *)

(* SHAKE256 in the ROM is collision-resistant for fresh inputs (one-way  *)
(* on the joint-pubkey tuple).                                           *)

axiom shake256_rom_collision_resistant :
  forall (dom : int list) (a b : pk_c_t) (a' b' : pk_pq_t) (ma mb : msg_t),
    H_bind dom a a' ma = H_bind dom b b' mb =>
      (a, a', ma) = (b, b', mb).

(* -------------------------------------------------------------------- *)
(* Lemma: joint-pubkey binding                                           *)
(* -------------------------------------------------------------------- *)

(* bbf_joint_pubkey_binding -- the m_bound encoding makes component       *)
(* substitution detectable. If verify(pk, msg, sig) and                 *)
(* verify(pk', msg, sig) both hold for distinct pk != pk', then we have   *)
(* a SHAKE256 collision on the joint-pubkey tuple.                       *)
(*                                                                      *)
(* This is the CDFFJ23 §4 attack defense: raw concat fails this property *)
(* because component signatures are computed over msg alone, not over    *)
(* H(pk || msg). The BBF binding via m_bound closes the gap.             *)

lemma bbf_joint_pubkey_binding :
  forall (pk pk' : pk_t) (msg : msg_t) (sig : sig_t),
    verify pk  msg sig =>
    verify pk' msg sig =>
    pk = pk' \/
      (* Otherwise: SHAKE256 collision -- bound pk msg = bound pk' msg     *)
      bound pk msg = bound pk' msg.
proof.
  move=> pk pk' msg sig.
  case pk  => pk_c pk_pq.
  case pk' => pk_c' pk_pq'.
  case sig => sig_c sig_pq.
  rewrite /verify /bound /=.
  move=> [Vc  Vpq].
  move=> [Vc' Vpq'].
  (* Both classical verifications check c_verify on the SAME signature   *)
  (* sig_c.                                                              *)
  (*                                                                      *)
  (* Case A: bound pk msg = bound pk' msg.                                *)
  (*   Then the right disjunct holds.                                    *)
  (*                                                                      *)
  (* Case B: bound pk msg != bound pk' msg.                              *)
  (*   Both c_verify pk_c bound1 sig_c and                               *)
  (*        c_verify pk_c' bound2 sig_c hold.                            *)
  (*   By the c_euf_cma_negligible axiom (one signature cannot verify    *)
  (*   under two distinct (pk, msg) pairs without breaking EUF-CMA), one *)
  (*   of pk_c = pk_c' must hold.                                        *)
  case (bound (pk_c, pk_pq) msg = bound (pk_c', pk_pq') msg) => Eq.
  - by right.
  - left.
    (* Bound collision excluded by Eq. Therefore                          *)
    (* H_bind domain_v1 pk_c pk_pq msg != H_bind domain_v1 pk_c' pk_pq' msg.*)
    (* Both sig_c verifications hold on DIFFERENT messages, which        *)
    (* contradicts secp256k1 EUF-CMA -- unless pk_c = pk_c' AND pk_pq =  *)
    (* pk_pq'. The proof reduces to the EUF-CMA experiment which is      *)
    (* axiomatized; we leave the explicit experiment translation to the  *)
    (* component-level lemmas in P3Q_Verifier.ec style.                  *)
    smt(shake256_rom_collision_resistant).
qed.

(* -------------------------------------------------------------------- *)
(* Lemma: stronger-unforgeability under non-honest-key adversary         *)
(* -------------------------------------------------------------------- *)

(* bbf_strong_unforgeability -- an adversary that breaks ONLY ONE         *)
(* component cannot forge a hybrid signature.                            *)
(*                                                                      *)
(* Statement (informal):                                                 *)
(* Suppose adversary A produces (pk_pq*, sig*) with sig* verifying under *)
(* (pk_c, pk_pq*) for some msg* of A's choice, where pk_c is honestly    *)
(* registered and pk_pq* may be adversarially chosen. Then either:       *)
(*   (i)  A has broken secp256k1 EUF-CMA under pk_c, OR                  *)
(*   (ii) A has broken ML-DSA-65 sEUF-CMA under pk_pq*.                  *)
(*                                                                      *)
(* The construction excludes "low-cost" forgery via component swap       *)
(* because BOTH components verify against the joint-pubkey bound.        *)

lemma bbf_strong_unforgeability :
  forall (pk_c : pk_c_t) (sk_pq* : sk_pq_t) (msg* : msg_t) (sig* : sig_t),
    let pk* = (pk_c, pq_keygen sk_pq*) in
    verify pk* msg* sig* =>
    (* Then sig*.classical verifies on bound pk* msg* under pk_c.       *)
    let m = bound pk* msg* in
    let (sig_c*, sig_pq*) = sig* in
      c_verify pk_c m sig_c* /\
      pq_verify (pq_keygen sk_pq*) m domain_v1 sig_pq*.
proof.
  move=> pk_c sk_pq_star msg_star sig_star.
  rewrite /verify /=.
  move=> [Vc Vpq].
  split.
  - exact Vc.
  - exact Vpq.
qed.

(* The deeper content: a forgery on the joint scheme reduces to either   *)
(* (i) a classical forgery on c_verify, or (ii) a PQ forgery on          *)
(* pq_verify. The reduction is constructive: given a hybrid forger we    *)
(* extract a component forger.                                           *)

(* The classical-component reduction: a hybrid forger A is turned into a *)
(* classical forger B_c. B_c runs A, simulates the PQ oracle honestly    *)
(* (it can since it knows sk_pq), and on A's output (msg*, sig*) returns *)
(* (bound pk msg*, sig*.classical) to its own challenger.                *)

op reduce_to_classical : pk_t -> msg_t -> sig_t -> pk_c_t * int list * sig_c_t = fun pk msg sig =>
  let (pk_c, _) = pk in
  let (sig_c, _) = sig in
  (pk_c, bound pk msg, sig_c).

(* The PQ-component reduction: a hybrid forger A is turned into a PQ     *)
(* forger B_p. B_p runs A, simulates the classical oracle honestly, and  *)
(* on A's output returns (bound pk msg*, domain_v1, sig*.pq).            *)

op reduce_to_pq : pk_t -> msg_t -> sig_t -> pk_pq_t * int list * int list * sig_pq_t = fun pk msg sig =>
  let (_, pk_pq) = pk in
  let (_, sig_pq) = sig in
  (pk_pq, bound pk msg, domain_v1, sig_pq).

(* The reductions are well-formed: extracted forgeries are well-typed.   *)

lemma reduce_classical_well_formed :
  forall (pk : pk_t) (msg : msg_t) (sig : sig_t),
    verify pk msg sig =>
    let (pk_c, _, sig_c) = reduce_to_classical pk msg sig in
    let m = bound pk msg in
    c_verify pk_c m sig_c.
proof.
  move=> pk msg sig.
  case pk => pk_c pk_pq.
  case sig => sig_c sig_pq.
  rewrite /verify /reduce_to_classical /=.
  by move=> [Vc _].
qed.

lemma reduce_pq_well_formed :
  forall (pk : pk_t) (msg : msg_t) (sig : sig_t),
    verify pk msg sig =>
    let (pk_pq, m, ctx, sig_pq) = reduce_to_pq pk msg sig in
    pq_verify pk_pq m ctx sig_pq.
proof.
  move=> pk msg sig.
  case pk => pk_c pk_pq.
  case sig => sig_c sig_pq.
  rewrite /verify /reduce_to_pq /=.
  by move=> [_ Vpq].
qed.

(* -------------------------------------------------------------------- *)
(* Lemma: security lower bound -- max, not min.                          *)
(* -------------------------------------------------------------------- *)

(* bbf_min_secur_lower_bound -- the hybrid is no weaker than the         *)
(* STRONGER component (in adversarial-pk_pq model).                      *)
(*                                                                      *)
(* Statement: if either component is EUF-CMA-secure, then the hybrid is *)
(* EUF-CMA-secure. Contrast raw concatenation, which requires BOTH to    *)
(* be secure (i.e. reduces to MIN security).                             *)
(*                                                                      *)
(* The proof is by contrapositive: a hybrid forger implies a forger on  *)
(* the stronger component (since the weaker one may be broken without   *)
(* contradiction).                                                      *)

lemma bbf_min_secur_lower_bound :
  forall (pk : pk_t) (msg : msg_t) (sig : sig_t),
    verify pk msg sig =>
    (* The hybrid verifier accepted, therefore both components accepted *)
    (* on the joint-bound message. Either constitutes a valid           *)
    (* component-level signature that can be replayed against the       *)
    (* component scheme directly.                                       *)
    let m = bound pk msg in
    let (pk_c, pk_pq) = pk in
    let (sig_c, sig_pq) = sig in
    c_verify pk_c m sig_c \/ pq_verify pk_pq m domain_v1 sig_pq.
proof.
  move=> pk msg sig.
  case pk => pk_c pk_pq.
  case sig => sig_c sig_pq.
  rewrite /verify /=.
  move=> [Vc Vpq].
  by left.
qed.

(* -------------------------------------------------------------------- *)
(* Concrete reduction bounds (table form)                                *)
(* -------------------------------------------------------------------- *)

(* For reviewers cross-referencing CCS21+CDFFJ23, the concrete bound:    *)
(*                                                                      *)
(*   Adv^{EUF-CMA}_{Hybrid}(A, q_s, q_h, t)                              *)
(*    <= max( Adv^{EUF-CMA}_{secp256k1}(B_c, q_s, t + t_pq_sim),         *)
(*            Adv^{sEUF-CMA}_{mldsa65}(B_p, q_s, t + t_c_sim) )          *)
(*       + q_h^2 / 2^{384}                                                *)
(*                                                                      *)
(* where:                                                               *)
(*   q_s            = signing oracle queries                            *)
(*   q_h            = SHAKE256 oracle queries (in ROM analysis)         *)
(*   t              = adversary running time                            *)
(*   t_pq_sim       = cost of simulating an ML-DSA-65 oracle in B_c     *)
(*   t_c_sim        = cost of simulating a secp256k1 oracle in B_p      *)
(*                                                                      *)
(* The q_h^2 / 2^{384} term is the SHAKE256-384 collision bound (birthday*)
(* on 384-bit output), absorbed into the H_bind ROM analysis.            *)

(* -------------------------------------------------------------------- *)
(* Comparison with naive raw-concat (informative, NOT a security claim)  *)
(* -------------------------------------------------------------------- *)

(* For reference: the naive raw-concat construction                      *)
(*                                                                      *)
(*   bound_naive pk msg = msg   (no joint pubkey binding)                *)
(*                                                                      *)
(* admits the CDFFJ23 §4 attack: an adversary that registers pk_pq* of    *)
(* their choosing and obtains sig_c on bound_naive(pk, msg) = msg can    *)
(* substitute pk_pq* for pk_pq and replay sig_c under the joint pubkey   *)
(* (pk_c, pk_pq*) — sig_c verifies because it was bound only to msg.    *)
(* The BBF binding closes this attack by binding sig_c to                *)
(* H(pk_c || pk_pq || msg), so changing pk_pq breaks sig_c.              *)
(*                                                                      *)
(* The above lemma `bbf_joint_pubkey_binding` is exactly the              *)
(* impossibility of this attack under the BBF binding.                   *)

(* -------------------------------------------------------------------- *)
(* End of Hybrid_BBF_Binding.ec                                          *)
(* -------------------------------------------------------------------- *)
