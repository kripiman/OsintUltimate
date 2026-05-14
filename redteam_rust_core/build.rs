fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "sovereign")]
    {
        tonic_build::configure()
            .build_server(false)
            .compile_protos(
                &[
                    "proto/sliver/clientpb/client.proto",
                    "proto/sliver/commonpb/common.proto",
                    "proto/sliver/dnspb/dns.proto",
                    "proto/sliver/sliverpb/sliver.proto",
                    "proto/sliver/rpcpb/services.proto",
                ],
                &["proto/sliver"],
            )?;
    }
    Ok(())
}
