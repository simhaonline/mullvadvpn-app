package net.mullvad.mullvadvpn.ui.widget

import android.content.Context
import android.text.method.DigitsKeyListener
import android.util.AttributeSet
import android.widget.TextView
import net.mullvad.mullvadvpn.R

private const val MIN_MTU_VALUE = 1280
private const val MAX_MTU_VALUE = 1420

class MtuCell : InputCell {
    var value: Int?
        get() = text.trim().toIntOrNull()
        set(value) {
            text = value?.toString() ?: ""
        }

    var onSubmitMtu: ((Int?) -> Unit)? = null

    constructor(context: Context) : super(context, TextView(context)) {}

    constructor(context: Context, attributes: AttributeSet) :
        super(context, attributes, TextView(context)) {}

    constructor(context: Context, attributes: AttributeSet, defaultStyleAttribute: Int) :
        super(context, attributes, defaultStyleAttribute, TextView(context)) {}

    constructor(
        context: Context,
        attributes: AttributeSet,
        defaultStyleAttribute: Int,
        defaultStyleResource: Int
    ) : super(
        context,
        attributes,
        defaultStyleAttribute,
        defaultStyleResource,
        TextView(context)
    ) {}

    init {
        input.apply {
            @Suppress("DEPRECATION")
            keyListener = DigitsKeyListener()
        }

        isValidInput = { input ->
            val value = input.toString().trim().toIntOrNull()

            value != null && value >= MIN_MTU_VALUE && value <= MAX_MTU_VALUE
        }

        onSubmitText = { input ->
            val mtu = input.toString().trim().toIntOrNull()

            if (mtu != null && mtu >= MIN_MTU_VALUE && mtu <= MAX_MTU_VALUE) {
                onSubmitMtu?.invoke(mtu)
            } else if (input.isEmpty()) {
                onSubmitMtu?.invoke(null)
            }
        }

        footer?.text =
            context.getString(R.string.wireguard_mtu_footer, MIN_MTU_VALUE, MAX_MTU_VALUE)
    }
}
