# Detection Note — T1525 (Persist via Lambda Layer)

**Signal:** lambda:PublishLayerVersion followed by lambda:UpdateFunctionConfiguration adding an unexpected layer — especially a newly created layer from an unknown principal

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
