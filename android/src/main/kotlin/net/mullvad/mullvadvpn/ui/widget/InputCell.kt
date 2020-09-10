package net.mullvad.mullvadvpn.ui.widget

import android.content.Context
import android.text.Editable
import android.text.TextWatcher
import android.util.AttributeSet
import android.view.LayoutInflater
import android.widget.EditText
import android.widget.TextView
import kotlin.properties.Delegates.observable
import net.mullvad.mullvadvpn.R

open class InputCell : Cell {
    private val validInputColor = context.getColor(R.color.white)
    private val invalidInputColor = context.getColor(R.color.red)

    protected val input =
        (LayoutInflater.from(context).inflate(R.layout.input_cell, null) as EditText).apply {
            val height = resources.getDimensionPixelSize(R.dimen.cell_input_height)

            layoutParams = LayoutParams(LayoutParams.WRAP_CONTENT, height, 0.0f)
            minWidth = resources.getDimensionPixelSize(R.dimen.cell_input_width)

            addTextChangedListener(InputWatcher())
            setOnFocusChangeListener { _, newHasFocus -> hasFocus = newHasFocus }
        }

    var hasFocus by observable(false) { _, oldValue, newValue ->
        if (oldValue == true && newValue == false) {
            onSubmitText?.invoke(text)
        }
    }
        private set

    var text: String
        get() = input.text.toString()
        set(value) = input.setText(value)

    var isValidInput: ((String) -> Boolean)? = null
    var onSubmitText: ((String) -> Unit)? = null

    constructor(context: Context, footer: TextView? = null) : super(context, footer) {}

    constructor(context: Context, attributes: AttributeSet, footer: TextView? = null) :
        super(context, attributes, footer) {}

    constructor(
        context: Context,
        attributes: AttributeSet,
        defaultStyleAttribute: Int,
        footer: TextView? = null
    ) : super(context, attributes, defaultStyleAttribute, footer) {}

    constructor(
        context: Context,
        attributes: AttributeSet,
        defaultStyleAttribute: Int,
        defaultStyleResource: Int,
        footer: TextView? = null
    ) : super(
        context,
        attributes,
        defaultStyleAttribute,
        defaultStyleResource,
        footer
    ) {}

    init {
        cell.setEnabled(false)
        cell.addView(input)
    }

    inner class InputWatcher : TextWatcher {
        override fun beforeTextChanged(text: CharSequence, start: Int, count: Int, after: Int) {}

        override fun onTextChanged(text: CharSequence, start: Int, count: Int, after: Int) {}

        override fun afterTextChanged(text: Editable) {
            if (isValidInput?.invoke(text.toString()) ?: true) {
                input.setTextColor(validInputColor)
            } else {
                input.setTextColor(invalidInputColor)
            }
        }
    }
}
