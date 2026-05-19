use crate::utils::executor::ExecutorMode;
use crate::plugins::config::GlobalConfig;
use crate::plugins::DiscoveryPlugin;

pub fn get_all_discovery<M: ExecutorMode>(config: GlobalConfig<M>) -> Vec<Box<dyn DiscoveryPlugin>> {
    use crate::plugins::reconnaissance::osint::engine::OsintScanner;
    use crate::plugins::reconnaissance::osint::subfinder::SubfinderScanner;
    use crate::plugins::reconnaissance::osint::amass::AmassScanner;
    use crate::plugins::reconnaissance::osint::uncover::UncoverScanner;
    use crate::plugins::reconnaissance::osint::sovereign_recon::SovereignReconScanner;
    use crate::plugins::reconnaissance::osint::alterx::AlterXScanner;
    use crate::plugins::reconnaissance::osint::puredns::PurednsScanner;
    use crate::plugins::reconnaissance::osint::bbscope::BBScopeScanner;
    use crate::plugins::reconnaissance::osint::shuffledns::ShufflednsScanner;
    use crate::plugins::reconnaissance::active::asnmap::AsnmapScanner;

    vec![
        Box::new(SovereignReconScanner::new(&crate::utils::config::Config::from_env(), config.proxy_manager.clone())),
        Box::new(OsintScanner::new(config.proxy_manager.clone())), 
        Box::new(SubfinderScanner::new(config.proxy_manager.clone())), 
        Box::new(AmassScanner::new()),
        Box::new(UncoverScanner::new()), 
        Box::new(AlterXScanner::new()),
        Box::new(PurednsScanner::new(config.proxy_manager.clone())),
        Box::new(BBScopeScanner::new(&config)),
        Box::new(ShufflednsScanner::new(&config)),
        Box::new(AsnmapScanner::new()),
    ]
}
