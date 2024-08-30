// Copyright 2024, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bellman::{
    bn256::{Bn256, Fq, Fq2, FqRepr, Fr, FrRepr, G1Affine, G2Affine},
    plonk::better_better_cs::cs::VerificationKey,
    CurveAffine, PrimeField,
};

use super::ZkSyncSnarkEthCircuit;

/// The type alias for ZkSync ethereum verification key.
pub type ZkSyncEthVk = VerificationKey<Bn256, ZkSyncSnarkEthCircuit>;

/// Return the default ZkSync ethereum verification key.
pub fn default() -> ZkSyncEthVk {
    let mut vk = ZkSyncEthVk::empty();
    vk.n = 16777215;
    vk.num_inputs = 1;
    vk.state_width = 4;
    vk.num_witness_polys = 0;
    vk.gate_setup_commitments = vec![
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                5391499613343178126,
                15986839001871063906,
                15676621201688856967,
                283626712550177443,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                1936932697761134675,
                7468961640795974446,
                4123303972047989667,
                2664732312013267457,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                11488992528554025682,
                12016824828223971094,
                11942004360057333370,
                316831626296641307,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                304673622018339856,
                7139037552557818730,
                12475560967982555143,
                1055588351918295250,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                2274984630539920017,
                5398167177582250136,
                16440396753384808945,
                1037682586893548769,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                10168660308952593373,
                16526369642614237721,
                569062739734175056,
                155645558476901406,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                14005362797509427677,
                2662603874351919260,
                14261489165672308143,
                1470528288349794782,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                11144229651170108862,
                11439490264313454962,
                114993091474760680,
                1037267173208738614,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                10726125240955612787,
                1916320162213728495,
                1058608086768277905,
                1651114031905829493,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                13237242732587628574,
                4774776044666137690,
                14401013098807103799,
                2514139699916115771,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                14434760601334248377,
                5316938318287831815,
                6221098547630910324,
                980422841280734466,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                9201886393750447942,
                3840149540273146267,
                18179910191622136829,
                1563809864380914603,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                6817966528197671686,
                17740237425164592147,
                16441545282615287931,
                2041286648005729125,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                9474748579292707241,
                15240396123572941358,
                12183160623197826566,
                395165462349679462,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                11830690209042008764,
                11761396005838073769,
                18271188400274886574,
                2896734446482773484,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                1890606551566554401,
                10220931290312275762,
                3256711195869515344,
                2466626485328709457,
            ]))
            .unwrap(),
        ),
    ];
    vk.gate_selectors_commitments = vec![
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                10865727529243127085,
                4083978853392244827,
                14303622309482785753,
                2263042021033673595,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                3019601017411802529,
                880444282195426618,
                9998743525359587628,
                2891421025832200233,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                5208608554346323426,
                8575970970223832576,
                2966209169082345602,
                239576408267301488,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                17715084817752316452,
                2726293100894160682,
                17920596859559317135,
                3485576345363305439,
            ]))
            .unwrap(),
        ),
    ];
    vk.permutation_commitments = vec![
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                14761045450946573029,
                17157644513453531531,
                2555518804134782053,
                1415819224310783987,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                17265629196749977462,
                4128711855633066822,
                8435602817910411328,
                1408116296902303196,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                3307267823832528482,
                2406249680085831639,
                9091964031261402109,
                2846274000290842933,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                17374905554931807856,
                6690578002079222163,
                11809376320193686210,
                2676076649992974574,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                3159118708748226574,
                5508845413629697013,
                13350869305506486049,
                689297560178790472,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                15696011303896469684,
                12551611148155235140,
                14438660833518031207,
                425021756161657108,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                18349397811516917436,
                4473982696343317918,
                13070312540813307819,
                2109468484629113245,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                13254534552549721008,
                17388411854346636521,
                17875890960520499518,
                1062184221180884481,
            ]))
            .unwrap(),
        ),
    ];
    vk.total_lookup_entries_length = 1787472;
    vk.lookup_selector_commitment = Some(G1Affine::from_xy_unchecked(
        Fq::from_repr(FqRepr([
            9324906502432882695,
            14977861238256290580,
            12538013124354067293,
            3408438202312564138,
        ]))
        .unwrap(),
        Fq::from_repr(FqRepr([
            14942105932194201701,
            12210090881357612547,
            14774705021036784261,
            2531694948512337448,
        ]))
        .unwrap(),
    ));
    vk.lookup_tables_commitments = vec![
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                10873859091125335643,
                3906092213625635374,
                17046157606087980048,
                3193402705223440293,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                10158946293873382504,
                2171386304067884865,
                6918663094168980658,
                350601565475975409,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                12822112641313049260,
                3646552465186399021,
                10324071010773924047,
                2209084192380614662,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                11045141628975531869,
                12589678537679955590,
                3065046617868727674,
                2099447669854151830,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                11395032673621937545,
                3000063650268118516,
                7857619430005721792,
                805706808484810738,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                6817063666434679427,
                1646386051225388537,
                4677946977082722827,
                1369650305976868514,
            ]))
            .unwrap(),
        ),
        G1Affine::from_xy_unchecked(
            Fq::from_repr(FqRepr([
                2885179371868476351,
                159944842081142878,
                6092294387055034894,
                213843603626505240,
            ]))
            .unwrap(),
            Fq::from_repr(FqRepr([
                11868113133779277990,
                8509646480531194854,
                14088068011597639414,
                707070630614027545,
            ]))
            .unwrap(),
        ),
    ];
    vk.lookup_table_type_commitment = Some(G1Affine::from_xy_unchecked(
        Fq::from_repr(FqRepr([
            1732877442096985191,
            7537030715658833452,
            14073502080301311448,
            2178792007727681099,
        ]))
        .unwrap(),
        Fq::from_repr(FqRepr([
            8513095304113652904,
            6581396660744182779,
            13939755637576387431,
            2477157044961106453,
        ]))
        .unwrap(),
    ));
    vk.non_residues = vec![
        Fr::from_repr(FrRepr([5, 0, 0, 0])).unwrap(),
        Fr::from_repr(FrRepr([7, 0, 0, 0])).unwrap(),
        Fr::from_repr(FrRepr([10, 0, 0, 0])).unwrap(),
    ];
    vk.g2_elements = [
        G2Affine::from_xy_unchecked(
            Fq2 {
                c0: Fq::from_repr(FqRepr([
                    5106727233969649389,
                    7440829307424791261,
                    4785637993704342649,
                    1729627375292849782,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    10945020018377822914,
                    17413811393473931026,
                    8241798111626485029,
                    1841571559660931130,
                ]))
                .unwrap(),
            },
            Fq2 {
                c0: Fq::from_repr(FqRepr([
                    5541340697920699818,
                    16416156555105522555,
                    5380518976772849807,
                    1353435754470862315,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    6173549831154472795,
                    13567992399387660019,
                    17050234209342075797,
                    650358724130500725,
                ]))
                .unwrap(),
            },
        ),
        G2Affine::from_xy_unchecked(
            Fq2 {
                c0: Fq::from_repr(FqRepr([
                    9089143573911733168,
                    11482283522806384523,
                    13585589533905622862,
                    79029415676722370,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    5692040832573735873,
                    16884514497384809355,
                    16717166481813659368,
                    2742131088506155463,
                ]))
                .unwrap(),
            },
            Fq2 {
                c0: Fq::from_repr(FqRepr([
                    9604638503594647125,
                    1289961608472612514,
                    6217038149984805214,
                    2521661352385209130,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    17168069778630926308,
                    11309277837895768996,
                    15154989611154567813,
                    359271377050603491,
                ]))
                .unwrap(),
            },
        ),
    ];
    vk
}

#[cfg(test)]
mod should {
    use super::*;
    use tests::assert_vk_eq;

    #[test]
    fn default_return_the_same_vk_from_json_file() {
        let vk = serde_json::from_reader::<_, ZkSyncEthVk>(
            std::fs::File::open("./resources/vk.json").unwrap(),
        )
        .unwrap();

        assert_vk_eq!(vk, default());
    }
}
