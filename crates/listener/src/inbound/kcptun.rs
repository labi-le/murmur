use murmur_listener_config::kcptun as lc_kcptun;
use murmur_transport_kcptun::common::Config as KcptunTransportConfig;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct KcpTun {
    pub enable: bool,
    pub key: String,
    pub crypt: String,
    pub mode: String,
    pub conn: i32,
    pub auto_expire: i32,
    pub scavenge_ttl: i32,
    pub mtu: i32,
    pub rate_limit: i32,
    pub snd_wnd: i32,
    pub rcv_wnd: i32,
    pub data_shard: i32,
    pub parity_shard: i32,
    pub dscp: i32,
    pub no_comp: bool,
    pub ack_nodelay: bool,
    pub no_delay: i32,
    pub interval: i32,
    pub resend: i32,
    pub no_congestion: i32,
    pub sock_buf: i32,
    pub smux_ver: i32,
    pub smux_buf: i32,
    pub frame_size: i32,
    pub stream_buf: i32,
    pub keep_alive: i32,
}

impl KcpTun {
    #[must_use]
    pub fn build(&self) -> lc_kcptun::KcpTun {
        lc_kcptun::KcpTun {
            enable: self.enable,
            config: KcptunTransportConfig {
                key: self.key.clone(),
                crypt: self.crypt.clone(),
                mode: self.mode.clone(),
                conn: self.conn,
                auto_expire: self.auto_expire,
                scavenge_ttl: self.scavenge_ttl,
                mtu: self.mtu,
                rate_limit: self.rate_limit,
                snd_wnd: self.snd_wnd,
                rcv_wnd: self.rcv_wnd,
                data_shard: self.data_shard,
                parity_shard: self.parity_shard,
                dscp: self.dscp,
                no_comp: self.no_comp,
                ack_nodelay: self.ack_nodelay,
                no_delay: self.no_delay,
                interval: self.interval,
                resend: self.resend,
                no_congestion: self.no_congestion,
                sock_buf: self.sock_buf,
                smux_ver: self.smux_ver,
                smux_buf: self.smux_buf,
                frame_size: self.frame_size,
                stream_buf: self.stream_buf,
                keep_alive: self.keep_alive,
            },
        }
    }
}
