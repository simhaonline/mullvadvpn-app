package net.mullvad.mullvadvpn.service

import android.content.Context
import java.net.InetAddress
import kotlin.properties.Delegates.observable
import org.apache.commons.validator.routines.InetAddressValidator

private const val SHARED_PREFERENCES = "custom_dns"
private const val KEY_ADDRESS = "address"

class CustomDns(context: Context) {
    companion object {
        private val STARTING_SLASH = Regex("^/")
    }

    private val preferences = context.getSharedPreferences(SHARED_PREFERENCES, Context.MODE_PRIVATE)

    var dnsServerAddress by observable<InetAddress?>(loadCustomDns()) { _, _, address ->
        onChange?.invoke(address)
        persist()
    }

    var onChange: ((InetAddress?) -> Unit)? = null

    private fun persist() {
        preferences.edit().apply {
            val rawDnsServerAddress = dnsServerAddress?.toString() ?: ""

            putString(KEY_ADDRESS, rawDnsServerAddress.replace(STARTING_SLASH, ""))
            apply()
        }
    }

    private fun loadCustomDns(): InetAddress? {
        return preferences.getString(KEY_ADDRESS, null)?.let { address ->
            if (InetAddressValidator.getInstance().isValid(address)) {
                InetAddress.getByName(address)
            } else {
                null
            }
        }
    }
}
