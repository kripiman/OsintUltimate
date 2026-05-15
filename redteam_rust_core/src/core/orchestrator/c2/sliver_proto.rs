#[cfg(feature = "sovereign")]
pub mod sliver {
    pub mod commonpb {
        tonic::include_proto!("commonpb");
    }
    pub mod clientpb {
        tonic::include_proto!("clientpb");
    }
    pub mod sliverpb {
        tonic::include_proto!("sliverpb");
    }
    pub mod dnspb {
        tonic::include_proto!("dnspb");
    }
    pub mod rpcpb {
        tonic::include_proto!("rpcpb");
    }
}
