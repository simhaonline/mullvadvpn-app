package net.mullvad.mullvadvpn.service

import java.net.InetAddress
import kotlin.properties.Delegates.observable

class CustomDns {
    var dnsServerAddress by observable<InetAddress?>(null) { _, _, address ->
        onChange?.invoke(address)
    }

    var onChange: ((InetAddress?) -> Unit)? = null
}
