package com.intel.i40eaqdebug.api.header;

import java.util.LinkedHashMap;
import java.util.Map;

public interface CommandStruct {

    /**
     * @return the name of the command struct: use
     */
    @Deprecated
    String getName();

    LinkedHashMap<String, CommandField> getFields();
}
