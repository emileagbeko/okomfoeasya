from pyteal import *

def defect_check_contract():
    # Global state
    total_defects_key = Bytes("total_defects")
    version_key = Bytes("version")
    
    # Initialize
    on_create = Seq([
        App.globalPut(total_defects_key, Int(0)),
        App.globalPut(version_key, Bytes("1.0.0")),
        Approve()
    ])
    
    # Record defect (NO ADMIN CHECK - automatic submission)
    defect_id = Txn.application_args[1]
    defect_hash = Txn.application_args[2]
    vehicle_id = Txn.application_args[3]
    severity = Txn.application_args[4]
    timestamp = Txn.application_args[5]
    
    record_defect = Seq([
        # Create Box (256 bytes) - Pop the return value
        Pop(App.box_create(defect_id, Int(256))),
        
        # Store data: hash(32) + vehicle_id(36) + timestamp(8) + severity(10)
        App.box_put(defect_id, Concat(
            defect_hash,
            vehicle_id,
            timestamp,
            severity
        )),
        
        # Increment counter
        App.globalPut(
            total_defects_key,
            App.globalGet(total_defects_key) + Int(1)
        ),
        
        Approve()
    ])
    
    # Verify defect
    verify_id = Txn.application_args[1]
    box_value = App.box_get(verify_id)
    
    verify_defect = Seq([
        box_value,
        Assert(box_value.hasValue()),
        Log(box_value.value()),
        Approve()
    ])
    
    # Router
    program = Cond(
        [Txn.application_id() == Int(0), on_create],
        [Txn.application_args[0] == Bytes("record"), record_defect],
        [Txn.application_args[0] == Bytes("verify"), verify_defect],
    )
    
    return program

if __name__ == "__main__":
    print(compileTeal(defect_check_contract(), mode=Mode.Application, version=8))
