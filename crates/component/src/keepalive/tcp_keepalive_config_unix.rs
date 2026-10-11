//! No platform probe: `socket2` applies the keep-alive idle/interval here and its refusal comes
//! back as an error, which the applier reports instead of skipping the option.
