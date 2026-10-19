/// The MPTCP toggle a dialer or listener config carries.
pub trait MultipathTcpFlag {
    fn set_multipath_tcp(&mut self, open: bool);
    fn multipath_tcp(&self) -> bool;
}

pub const MULTIPATH_TCP_AVAILABLE: bool = true;

pub fn set_net_dialer<D: MultipathTcpFlag>(dialer: &mut D, open: bool) {
    dialer.set_multipath_tcp(open);
}

pub fn get_net_dialer<D: MultipathTcpFlag>(dialer: &D) -> bool {
    dialer.multipath_tcp()
}

pub fn set_net_listen_config<L: MultipathTcpFlag>(listen_config: &mut L, open: bool) {
    listen_config.set_multipath_tcp(open);
}

pub fn get_net_listen_config<L: MultipathTcpFlag>(listen_config: &L) -> bool {
    listen_config.multipath_tcp()
}
