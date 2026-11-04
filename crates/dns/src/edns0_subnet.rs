use hickory_proto::op::Edns;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use ipnet::IpNet;

pub(crate) fn set_edns0_subnet(
    message: &mut hickory_proto::op::Message,
    client_subnet: IpNet,
    override_: bool,
) -> bool {
    let edns = message.edns.get_or_insert_with(Edns::new);
    let options = edns.options_mut();

    if !override_ && matches!(options.get(EdnsCode::Subnet), Some(EdnsOption::Subnet(_))) {
        return false;
    }

    let subnet = ClientSubnet::new(client_subnet.addr(), client_subnet.prefix_len(), 0);
    options.remove(EdnsCode::Subnet);
    options.insert(EdnsOption::Subnet(subnet));
    true
}
