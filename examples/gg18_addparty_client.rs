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
  let params: Params = serde_json::from_str(&data).unwrap();
  let PARTIES: u16 = params.parties.parse::<u16>().unwrap();
  let THRESHOLD: u16 = params.threshold.parse::<u16>().unwrap();

  let client = Client::new();

  // signup:
  let (party_num_int, uuid) = match signup(&client).unwrap() {
      PartySignup { number, uuid } => (number, uuid),
  };
  println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

  if party_num_int > PARTIES {
    call_new_party(PARTIES, THRESHOLD, &client, party_num_int, uuid.clone());
  } else {
    call_existing_party(PARTIES, THRESHOLD, &client, party_num_int, uuid.clone());
  }
}


pub fn call_new_party(
  PARTIES: u16,
  THRESHOLD: u16,
  client: &Client,
  party_num_int: u16,
  uuid: String,
) {
  // delay:
  let delay = time::Duration::from_millis(25);

  let party_keys = Keys::create(party_num_int as usize);

  // Posalji public key svima...
  for i in 1..=PARTIES {
    assert!(simple_send(
      &client,
      party_num_int,
      i,
      "np_pub_key",  // np stands for "new party"
      serde_json::to_string(&party_keys.y_i).unwrap(),
      uuid.clone(),
    )
    .is_ok());
  }

  // Pribavi javni kljuc od svih ostalih
  let mut pub_key_vec: Vec<GE> = Vec::new();
  for i in 1..=PARTIES {
    let orig_pub_key_ans = simple_poll(
      &client,
      i,
      party_num_int,
      delay,
      "orig_pub_key",
      uuid.clone(),
    );
    let pub_key: GE = serde_json::from_str(&orig_pub_key_ans).unwrap();
    pub_key_vec.push(pub_key.clone());
  }

  ///////////////////////////////////////////////////////////////////////////////
  for i in 1..=PARTIES {
    assert!(simple_send(
      &client,
      party_num_int,
      i,
      "np_paillier_key",
      serde_json::to_string(&party_keys.ek).unwrap(),
      uuid.clone(),
    )
    .is_ok());
  }

  // Pribavi javni kljuc od svih ostalih
  let mut paillier_key_vec: Vec<EncryptionKey> = Vec::new();
  for i in 1..=PARTIES {
    let orig_paillier_key_ans = simple_poll(
      &client,
      i,
      party_num_int,
      delay,
      "orig_paillier_key",
      uuid.clone(),
    );
    let paillier_key: EncryptionKey = serde_json::from_str(&orig_paillier_key_ans).unwrap();
    paillier_key_vec.push(paillier_key.clone());
  }

  //////////////////////////////////////////////////////////////////////////
  let vss_scheme_ans = simple_poll(
    &client,
    1,
    party_num_int,
    delay,
    "vss_scheme",
    uuid.clone(),
  );
  let vss_scheme: VerifiableSS = serde_json::from_str(&vss_scheme_ans).unwrap();
  for i in 2..=PARTIES {
    let vss_ans = simple_poll(
      &client,
      i,
      party_num_int,
      delay,
      "vss_scheme",
      uuid.clone(),
    );
    let vss: VerifiableSS = serde_json::from_str(&vss_ans).unwrap();
    assert!(vss == vss_scheme);
  }

  let y_sum_ans = simple_poll(
    &client,
    1,
    party_num_int,
    delay,
    "y_sum",
    uuid.clone(),
  );
  let y_sum: GE = serde_json::from_str(&y_sum_ans).unwrap();
  for i in 2..=PARTIES {
    let y_ans = simple_poll(
      &client,
      i,
      party_num_int,
      delay,
      "y_sum",
      uuid.clone(),
    );
    let y: GE = serde_json::from_str(&y_ans).unwrap();
    assert!(y_sum == y);
  }

  /////////////////////////////////////////////////////////
  let mut x_i: FE = FE::zero();
  for i in 1..=(THRESHOLD+1) {
    let share_part_ans = simple_poll(
      &client,
      i,
      party_num_int,
      delay,
      "share_part",
      uuid.clone(),
    );
    let share_part: FE = serde_json::from_str(&share_part_ans).unwrap();
    x_i = x_i + share_part;
  }

  let shared_keys: SharedKeys = SharedKeys {y: y_sum, x_i};

  // Add myself to public vectors
  paillier_key_vec.push(party_keys.ek.clone());

  let keygen_json = serde_json::to_string(&(
    party_keys,
    shared_keys,
    party_num_int,
    update_vss_scheme(&vss_scheme),
    paillier_key_vec,
    y_sum,
  ))
  .unwrap();

  let comm: GE = vss_scheme.get_point_commitment(party_num_int as usize);
  let g: GE = ECPoint::generator();
  let comm_expect: GE = g * x_i;
  assert!(comm == comm_expect);

  fs::write(env::args().nth(2).unwrap(), keygen_json).expect("Unable to save !");
}


///////////////////////////////////////////////////////
/////// ~~~~~~~ EXISTING PARTY ~~~~~~~~~ //////////////
///////////////////////////////////////////////////////
pub fn call_existing_party(
  PARTIES: u16,
  THRESHOLD: u16,
  client: &Client,
  party_num_int: u16,
  uuid: String,
) {
  // delay:
  let delay = time::Duration::from_millis(25);

  // Ucitaj keys{party_id}.store
  let data = fs::read_to_string(env::args().nth(2).unwrap())
    .expect("Unable to load keys, did you run keygen first? ");
  let (party_keys, shared_keys, party_id, vss_scheme, paillier_key_vector, y_sum): (
    Keys,
    SharedKeys,
    u16,
    VerifiableSS,
    Vec<EncryptionKey>,
    GE,
  ) = serde_json::from_str(&data).unwrap();

  // Pribavi javni kljuc od novog korisnika
  let np_pub_key_ans = simple_poll(
    &client,
    PARTIES + 1,
    party_num_int,
    delay,
    "np_pub_key",
    uuid.clone(),
  );
  let _np_y: GE = serde_json::from_str(&np_pub_key_ans).unwrap();

  // Posalji moj javni kljuc novoj stranci
  assert!(simple_send(
    &client,
    party_num_int,
    PARTIES + 1,
    "orig_pub_key",  // np stands for "new party"
    serde_json::to_string(&party_keys.y_i).unwrap(),
    uuid.clone(),
  )
  .is_ok());

  ///////////////////////////////////////////////////////////////////////////////
  let np_paillier_key_ans = simple_poll(
    &client,
    PARTIES + 1,
    party_num_int,
    delay,
    "np_paillier_key",
    uuid.clone(),
  );
  let np_ek: EncryptionKey = serde_json::from_str(&np_paillier_key_ans).unwrap();

  // Posalji moj paillier javni kljuc
  assert!(simple_send(
    &client,
    party_num_int,
    PARTIES + 1,
    "orig_paillier_key",
    serde_json::to_string(&party_keys.ek).unwrap(),
    uuid.clone(),
  )
  .is_ok());

  //////////////////////////////////////////////////////////////////
  assert!(simple_send(
    &client,
    party_num_int,
    PARTIES + 1,
    "vss_scheme",
    serde_json::to_string(&vss_scheme).unwrap(),
    uuid.clone(),
  )
  .is_ok());

  assert!(simple_send(
    &client,
    party_num_int,
    PARTIES + 1,
    "y_sum",
    serde_json::to_string(&y_sum).unwrap(),
    uuid.clone(),
  )
  .is_ok());

  ////////////////////////////////////////////////////////////////////
  if party_num_int <= THRESHOLD + 1 {
    let li: FE = li_at_x(
      &vss_scheme,
      (party_num_int - 1) as usize,
      (0..=(THRESHOLD as usize)).collect::<Vec<usize>>().as_slice(),
      (PARTIES + 1) as usize,
    );
    let np_x_part: FE = li * shared_keys.x_i;
    let mut random_sum: FE = FE::zero();
    for i in 1..=(THRESHOLD + 1) {
      if i != party_num_int {
        let random_value: FE = ECScalar::new_random();
        random_sum = random_sum + random_value;
        assert!(simple_send(
          &client,
          party_num_int,
          i,
          "random_value",
          serde_json::to_string(&random_value).unwrap(),
          uuid.clone(),
        )
        .is_ok());
      }
    }
    let mut my_part: FE = np_x_part.sub(&random_sum.get_element());
    assert!(my_part + random_sum == np_x_part);
    for i in 1..=(THRESHOLD + 1) {
      if i != party_num_int {
        let recv_value_ans = simple_poll(
          &client,
          i,
          party_num_int,
          delay,
          "random_value",
          uuid.clone(),
        );
        let recv_value: FE = serde_json::from_str(&recv_value_ans).unwrap();
        my_part = my_part + recv_value;
      }
    }

    // TODO: Encrypt with DH key before sending.
    // Adversary that eavedrops the network can easily reconstruct the share.
    assert!(simple_send(
      &client,
      party_num_int,
      PARTIES + 1,
      "share_part",
      serde_json::to_string(&my_part).unwrap(),
      uuid.clone(),
    )
    .is_ok());
  }

  // update data...
  // Write new party's Paillier encryption key
  let mut paillier_key_vec: Vec<EncryptionKey> = paillier_key_vector.clone();
  paillier_key_vec.push(np_ek);

  let keygen_json = serde_json::to_string(&(
    party_keys,
    shared_keys,
    party_num_int,
    update_vss_scheme(&vss_scheme),
    paillier_key_vec,
    y_sum,
  ))
  .unwrap();

  fs::write(env::args().nth(2).unwrap(), keygen_json).expect("Unable to save !");
}

pub fn signup(client: &Client) -> Result<PartySignup, ()> {
  let key = "signup-addparty".to_string();

  let res_body = postb(&client, "signupaddparty", key).unwrap();
  serde_json::from_str(&res_body).unwrap()
}

pub fn do_vecs_match<T: PartialEq>(a: &Vec<T>, b: &Vec<T>) -> bool {
  let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
  matching == a.len() && matching == b.len()
}

pub fn li_at_x(vss_scheme: &VerifiableSS, index: usize, s: &[usize], x: usize) -> FE {
  let s_len = s.len();
  let points: Vec<FE> = (0..vss_scheme.parameters.share_count)
    .map(|i| {
      let index_bn = BigInt::from((i + 1) as u32);
      ECScalar::from(&index_bn)
    })
    .collect::<Vec<FE>>();
  
  let x_fe: FE = ECScalar::from(&BigInt::from(x as u32));
  let xi = &points[index];
  let num: FE = ECScalar::from(&BigInt::one());
  let denum: FE = ECScalar::from(&BigInt::one());
  let num = (0..s_len).fold(num, |acc, i| {
    if s[i] != index {
      let x_sub_xj = x_fe.sub(&points[s[i]].get_element());
      acc * x_sub_xj
    } else {
      acc
    }
  });
  let denum = (0..s_len).fold(denum, |acc, i| {
    if s[i] != index {
      let xi_sub_xj = xi.sub(&points[s[i]].get_element());
      acc * xi_sub_xj
    } else {
      acc
    }
  });
  let denum = denum.invert();
  num * denum
}

pub fn update_vss_scheme(vss_scheme: &VerifiableSS) -> VerifiableSS {
  VerifiableSS {
    parameters: ShamirSecretSharing {
      threshold: vss_scheme.parameters.threshold,
      share_count: vss_scheme.parameters.share_count + 1,
    },
    commitments: vss_scheme.commitments.clone(),
  }
}