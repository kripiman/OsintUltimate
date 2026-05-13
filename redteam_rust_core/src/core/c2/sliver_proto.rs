#[cfg(feature = "sovereign")]
pub mod sliver {
    pub mod common {
        tonic::include_proto!("commonpb");
    }
    pub mod client {
        tonic::include_proto!("clientpb");
    }
    pub mod sliver {
        tonic::include_proto!("sliverpb");
    }
    pub mod dns {
        tonic::include_proto!("dnspb");
    }
    pub mod rpc {
        tonic::include_proto!("rpcpb");
    }
}
