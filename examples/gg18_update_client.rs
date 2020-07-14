#![allow(non_snake_case)]

use curv::{
  cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing, VerifiableSS,
  },
  elliptic::curves::traits::{ECPoint, ECScalar},
  BigInt, FE, GE,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
  Keys, Parameters, SharedKeys,
};
use paillier::EncryptionKey;
use reqwest::Client;
use std::{env, fs, time};

mod common;
use common::{
  simple_poll, simple_send, Params, PartySignup, postb,
  poll_for_broadcasts, broadcast
};

fn main() {
  if env::args().nth(3).is_some() {
    panic!("too many arguments")
  }
  if env::args().nth(2).is_none() {
    panic!("too few arguments")
  }

  // read parameters:
  let data = fs::read_to_string("params.json")
    .expect("Unable to read params, make sure config file is present in the same folder");
  let update_data = fs::read_to_string("update_params.json")
    .expect("Unable to read update_params.json.");
  
  let params: Params = serde_json::from_str(&data).unwrap();
  let PARTIES: u16 = params.parties.parse::<u16>().unwrap();
  let THRESHOLD: u16 = params.threshold.parse::<u16>().unwrap();
  let UPDATING: u16 = update_data.trim().to_string().parse::<u16>().unwrap();

  println!("koji vrag: {:?}", UPDATING);

  
  let client = Client::new();
  // delay:
  let delay = time::Duration::from_millis(25);

  // signup:
  let (party_num_int, uuid) = match signup(&client).unwrap() {
      PartySignup { number, uuid } => (number, uuid),
  };
  println!("number: {:?}, uuid: {:?}", party_num_int, uuid);
  

  let my_data = fs::read_to_string(env::args().nth(2).unwrap())
      .expect("Unable to load keys, did you run keygen first? ");
  let (party_keys, shared_keys, party_id, vss_scheme, paillier_key_vector, y_sum): (
    Keys,
    SharedKeys,
    u16,
    VerifiableSS,
    Vec<EncryptionKey>,
    GE,
  ) = serde_json::from_str(&my_data).unwrap();

  
  assert!(broadcast(
    &client,
    party_num_int,
    "round0",
    serde_json::to_string(&party_id).unwrap(),
    uuid.clone()
  )
  .is_ok());

  let round0_ans_vec = poll_for_broadcasts(
      &client,
      party_num_int,
      UPDATING,
      delay,
      "round0",
      uuid.clone(),
  );

  
  let mut j = 0;
  let mut updaters_vec: Vec<usize> = Vec::new();
  for i in 1..=UPDATING {
      if i == party_num_int {
          updaters_vec.push(party_id as usize);
      } else {
          let updater_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
          updaters_vec.push(updater_j as usize);
          j += 1;
      }
  }

  // sve osim slobodnog clana!
  let coef: Vec<FE> = sample_polynomial(THRESHOLD as usize);
  let subshares: Vec<FE> = evaluate_polynomial(&coef, &updaters_vec);
  let G: GE = ECPoint::generator();
  let commitments = (0..coef.len()).map(|i| G * coef[i]).collect::<Vec<GE>>();

  for i in 1..=UPDATING {
    if i != party_num_int {
      assert!(simple_send(
        &client,
        party_num_int,
        i,
        "subshare",
        serde_json::to_string(&subshares[(i - 1) as usize]).unwrap(),
        uuid.clone(),
      )
      .is_ok());

      assert!(simple_send(
        &client,
        party_num_int,
        i,
        "feldmans",
        serde_json::to_string(&commitments).unwrap(),
        uuid.clone(),
      )
      .is_ok());
    }
  }

  let mut updated_vss_scheme: VerifiableSS = vss_scheme.clone();
  let mut updated_x_i: FE = shared_keys.x_i.clone();

  for i in 1..=UPDATING {
    if i != party_num_int {
      let subshare_ans = simple_poll(
        &client,
        i,
        party_num_int,
        delay,
        "subshare",
        uuid.clone(),
      );
      let subshare: FE = serde_json::from_str(&subshare_ans).unwrap();
      let feldmans_ans = simple_poll(
        &client,
        i,
        party_num_int,
        delay,
        "feldmans",
        uuid.clone(),
      );
      // sve osim slobodnog clana
      let feldmans: Vec<GE> = serde_json::from_str(&feldmans_ans).unwrap();
      assert!(verify_feldman_commitments(THRESHOLD as usize, party_id as usize, subshare, &feldmans));

      updated_x_i = updated_x_i + subshare;
      updated_vss_scheme = update_vss(&updated_vss_scheme, &feldmans);
    }
  }

  updated_x_i = updated_x_i + subshares[(party_num_int - 1) as usize];
  updated_vss_scheme = update_vss(&updated_vss_scheme, &commitments);

  let update_json = serde_json::to_string(&(
    party_keys,
    SharedKeys { y: shared_keys.y, x_i: updated_x_i },
    party_id,
    updated_vss_scheme.clone(),
    paillier_key_vector,
    y_sum,
  ))
  .unwrap();

  let comm: GE = updated_vss_scheme.get_point_commitment(party_id as usize);
  let comm_expect: GE = G * updated_x_i;
  assert!(comm == comm_expect);

  fs::write(env::args().nth(2).unwrap(), update_json).expect("Unable to save !");
}


pub fn signup(client: &Client) -> Result<PartySignup, ()> {
  let key = "signup-update".to_string();

  let res_body = postb(&client, "signupupdate", key).unwrap();
  println!("SIGNUP: {:?}", res_body);
  serde_json::from_str(&res_body).unwrap()
}

pub fn sample_polynomial(t: usize) -> Vec<FE> {
  (1..=t).map(|_| ECScalar::new_random()).collect()
}

pub fn evaluate_polynomial(coefficients: &[FE], index_vec: &[usize]) -> Vec<FE> {
  (0..index_vec.len())
      .map(|point| {
          let point_bn = BigInt::from(index_vec[point] as u32);

          mod_evaluate_polynomial(coefficients, ECScalar::from(&point_bn))
      })
      .collect::<Vec<FE>>()
}

pub fn mod_evaluate_polynomial(coefficients: &[FE], point: FE) -> FE {
  let mut reversed_coefficients = coefficients.iter().rev();
  let head = FE::zero();
  reversed_coefficients.fold(head.clone(), |partial, coef| {
      let partial_add_coef = partial.add(&coef.get_element());
      partial_add_coef.mul(&point.get_element())
  })
}

pub fn verify_feldman_commitments(
    t: usize, index: usize, share: FE, commitments: &Vec<GE>) -> bool {
  let index_fe: FE = ECScalar::from(&BigInt::from(index as u32));
  let mut share_comm: GE = commitments[commitments.len() - 1].clone() * index_fe;
  for i in 2..=commitments.len() {
    share_comm = share_comm + commitments[commitments.len() - i].clone();
    share_comm = share_comm * index_fe;
  }
  let G: GE = ECPoint::generator();
  share_comm == G * share
}

pub fn update_vss(vss_scheme: &VerifiableSS, commitments: &Vec<GE>) -> VerifiableSS {
  let mut comm_vec: Vec<GE> = Vec::new();
  comm_vec.push(vss_scheme.commitments[0].clone());
  for i in 0..commitments.len() {
    comm_vec.push(vss_scheme.commitments[(i + 1) as usize] + commitments[i as usize]);
  }
  VerifiableSS {
    parameters: vss_scheme.parameters.clone(),
    commitments: comm_vec,
  }
}