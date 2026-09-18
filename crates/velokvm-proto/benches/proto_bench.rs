use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use snow::Builder;
use velokvm_proto::{
    AntiReplayWindow, ButtonFlags, PacketTag, RelMotionPacket, REL_MOTION_SIZE,
};

/// 測試資料準備：建立標準 RelMotionPacket 實體
fn create_dummy_packet() -> RelMotionPacket {
    RelMotionPacket {
        tag: PacketTag::RelMotion,
        flags: ButtonFlags(ButtonFlags::BTN_LEFT),
        sequence: 1024,
        timestamp_us: 500_000,
        dx: 12,
        dy: -8,
        wheel_v: 0,
        wheel_h: 0,
    }
}

/// 1. Bitpacking & Zero-Copy Transmute 效能評測
fn bench_bitpacking(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitpacking");
    group.throughput(Throughput::Bytes(REL_MOTION_SIZE as u64));

    let pkt = create_dummy_packet();

    group.bench_function("serialize_as_bytes", |b| {
        b.iter(|| {
            let bytes = black_box(&pkt).as_bytes();
            black_box(bytes);
        })
    });

    let raw_bytes = pkt.as_bytes();
    group.bench_function("deserialize_from_bytes", |b| {
        b.iter(|| {
            let parsed = RelMotionPacket::from_bytes(black_box(raw_bytes));
            black_box(parsed);
        })
    });

    group.finish();
}

/// 2. Anti-Replay Sliding Window 效能評測
fn bench_anti_replay(c: &mut Criterion) {
    let mut group = c.benchmark_group("anti_replay");
    let mut window = AntiReplayWindow::new();
    let mut seq = 1u64;

    group.bench_function("validate_and_update_sequential", |b| {
        b.iter(|| {
            let res = window.validate_and_update(black_box(seq));
            seq += 1;
            black_box(res);
        })
    });

    group.finish();
}

/// 3. Noise_IK 0-RTT 單一封包加解密 Full-Cycle 評測
fn bench_noise_ik_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("noise_ik_crypto");

    // 建立 Noise_IK 密鑰對
    let builder = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let static_key_initiator = builder.generate_keypair().unwrap();
    let static_key_responder = builder.generate_keypair().unwrap();

    // 初始化 Handshake State
    let mut initiator = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
        .local_private_key(&static_key_initiator.private)
        .remote_public_key(&static_key_responder.public)
        .build_initiator()
        .unwrap();

    let mut responder = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
        .local_private_key(&static_key_responder.private)
        .build_responder()
        .unwrap();

    // 0-RTT Message 1 握手 (-> e, es, s, ss)
    let mut msg1 = [0u8; 128];
    let mut payload_buf = [0u8; 128];
    let pkt = create_dummy_packet();

    let len1 = initiator.write_message(b"", &mut msg1).unwrap();
    responder.read_message(&msg1[..len1], &mut payload_buf).unwrap();

    // Message 2 握手 (<- e, ee)
    let mut msg2 = [0u8; 128];
    let len2 = responder.write_message(b"", &mut msg2).unwrap();
    initiator.read_message(&msg2[..len2], &mut payload_buf).unwrap();

    let mut initiator_transport = initiator.into_transport_mode().unwrap();

    let mut cipher_text = [0u8; 256];

    group.throughput(Throughput::Bytes(REL_MOTION_SIZE as u64));

    group.bench_function("encrypt_rel_motion", |b| {
        b.iter(|| {
            let len = initiator_transport
                .write_message(black_box(pkt.as_bytes()), black_box(&mut cipher_text))
                .unwrap();
            black_box(len);
        })
    });

    group.bench_function("decrypt_rel_motion", |b| {
        b.iter_batched(
            || {
                // 每組 iteration 準備乾淨的 transport state 與加密封包
                let b_init = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
                let b_resp = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
                let mut init = b_init
                    .local_private_key(&static_key_initiator.private)
                    .remote_public_key(&static_key_responder.public)
                    .build_initiator()
                    .unwrap();
                let mut resp = b_resp
                    .local_private_key(&static_key_responder.private)
                    .build_responder()
                    .unwrap();

                let mut m1 = [0u8; 128];
                let mut p_buf = [0u8; 128];
                let l1 = init.write_message(b"", &mut m1).unwrap();
                resp.read_message(&m1[..l1], &mut p_buf).unwrap();

                let mut m2 = [0u8; 128];
                let l2 = resp.write_message(b"", &mut m2).unwrap();
                init.read_message(&m2[..l2], &mut p_buf).unwrap();

                let mut tx = init.into_transport_mode().unwrap();
                let rx = resp.into_transport_mode().unwrap();

                let mut ct = [0u8; 256];
                let ct_len = tx.write_message(pkt.as_bytes(), &mut ct).unwrap();

                (rx, ct, ct_len)
            },
            |(mut rx, ct, ct_len)| {
                let mut pt = [0u8; 256];
                let dec_len = rx
                    .read_message(
                        black_box(&ct[..ct_len]),
                        black_box(&mut pt),
                    )
                    .unwrap();
                black_box(dec_len);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_bitpacking,
    bench_anti_replay,
    bench_noise_ik_crypto
);
criterion_main!(benches);
