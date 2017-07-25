#ifndef ROBINHOOD_HASH_H
#define ROBINHOOD_HASH_H

// "X macro" pattern is expected to be for this parameters:
// #define x_setvalue(index, key, val) is a macro to set value to the table cell
// #define x_setnil(index) is a macro that marks table entry as empty
// #define x_nilvalue is a value siganlizing that key is not found
// #define x_getvalue(index) is a macro to get value of the table cell
// #define x_getkey(index) is a macro for obtaining key for given index of the table.
// #define x_isnil(index) is a macro that checks if table entry is empty
// #define x_n_elem should point to number of buckets in hash table
// #define x_getbucket(key) is a macro for obtaining adviced 
//      index of the table of the given key. Should be in range [1, n_elem[.
// #define x_overflow is a macro that called when table is full
// #define x_removefailed(key) is a macro that called when trying to remove nonexisting element
// #define x_swap(index1, index2) is a macro that swaps two entries in the table

// hash table entry should consist only of key and value and x_setvalue should completely set an entry
// If you don't need value just use reuse key as value

// API:
#define ROBINHOOD_HASH_SET(key, value) \
       _ROBINHOOD_HASH_SET(key, value)
       
#define ROBINHOOD_HASH_GET(key, assignme) \
       _ROBINHOOD_HASH_GET(key, assignme)
       
#define ROBINHOOD_HASH_DEL(key) \
       _ROBINHOOD_HASH_DEL(key)
       
#define ROBINHOOD_HASH_SIZE(assignme) \
       _ROBINHOOD_HASH_SIZE(assignme)

// Impl:
       
#define _ROBINHOOD_HASH_GETKEYTEMP(i) \
    ((x_n_elem + i - x_getbucket(x_getkey(i)) - 1) % (x_n_elem-1))

#define _ROBINHOOD_HASH_TYPICAL_INIT(key) \
    int _rh_i = x_getbucket(key); \
    int _rh_i_orig = _rh_i; \
    int _rh_temperature = 0;
    
#define _ROBINHOOD_HASH_TYPICAL_INCREMENT(breakcode) \
    _rh_temperature += 1; \
    _rh_i += 1; \
    if (_rh_i>=x_n_elem) _rh_i=1; \
    if (_rh_i == _rh_i_orig) { \
        breakcode \
        break; \
    }

#define _ROBINHOOD_HASH_DEBUGPRINT { \
    int _rh_i; \
    printf("RBHDP: "); \
    for(_rh_i=1; _rh_i<x_n_elem; ++_rh_i) { \
        printf("%02d:",_rh_i); \
        if (x_isnil(_rh_i)) { \
            printf("___+__ "); \
        } else { \
            printf("%03u+%02d ", x_getkey(_rh_i), _ROBINHOOD_HASH_GETKEYTEMP(_rh_i)); \
        } \
    } \
    printf("\n"); \
}

#define _ROBINHOOD_HASH_SET(key, value)  { \
    _ROBINHOOD_HASH_TYPICAL_INIT(key) \
    x_setvalue(0, key, value); \
    int _rh_check_for_match = 1; \
    for(;;) { \
        if (x_isnil(_rh_i)) { \
            x_setvalue(_rh_i, x_getkey(0), x_getvalue(0)); \
            break; \
        } else { \
            if (_rh_check_for_match && x_getkey(_rh_i) == key) { \
                x_setvalue(_rh_i, key, value); \
                break; \
            } \
            int _rh_i_temp = _ROBINHOOD_HASH_GETKEYTEMP(_rh_i); \
            if (_rh_i_temp < _rh_temperature) { \
                /* Rob the rich, give the poor */ \
                x_swap(0, _rh_i); \
                _rh_temperature = _rh_i_temp; \
                _rh_check_for_match = 0; \
            } \
            _ROBINHOOD_HASH_TYPICAL_INCREMENT(x_overflow) \
        } \
    } \
}
    
#define _ROBINHOOD_HASH_GET(key, assignme) { \
    _ROBINHOOD_HASH_TYPICAL_INIT(key) \
    for(;;) { \
        if (x_isnil(_rh_i)) { \
            assignme = x_nilvalue; \
            break; \
        } else { \
            if (x_getkey(_rh_i) == key) { \
                assignme = x_getvalue(_rh_i); \
                break; \
            } \
            _ROBINHOOD_HASH_TYPICAL_INCREMENT(assignme = x_nilvalue;) \
        } \
    } \
}

#define _ROBINHOOD_HASH_DEL(key) { \
    _ROBINHOOD_HASH_TYPICAL_INIT(key) \
    int _ri_needbackshift = 0; \
    for(;;) { \
        if (x_isnil(_rh_i)) { \
            x_removefailed(key); \
            break; \
        } else { \
            if (x_getkey(_rh_i) == key) { \
                x_setnil(_rh_i); \
                _ri_needbackshift = 1; \
                break; \
            } \
            _ROBINHOOD_HASH_TYPICAL_INCREMENT(x_removefailed(key)) \
        } \
    } \
    /* Backshift */ \
    if(_ri_needbackshift)\
    for(;;) { \
        int _rh_nexti = _rh_i + 1; \
        if (_rh_nexti >= x_n_elem) _rh_nexti=1; \
        if (x_isnil(_rh_nexti)) { \
            break; \
        } else \
        if (x_getbucket(x_getkey(_rh_nexti)) == _rh_nexti) { \
            break; \
        } else { \
            x_swap(_rh_nexti, _rh_i); \
        } \
        _rh_i = _rh_nexti; \
    } \
}
    
#define _ROBINHOOD_HASH_SIZE(assignme) { \
    int _rh_i; \
    assignme = 0; \
    for(_rh_i=0; _rh_i<x_n_elem; ++_rh_i) { \
        if (!(x_isnil(_rh_i))) assignme+=1; \
    } \
}
    
#endif // ROBINHOOD_HASH_H
