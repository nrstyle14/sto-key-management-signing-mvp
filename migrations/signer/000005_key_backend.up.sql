-- 키별 서명기 종류(설계서 6.4·12.1, D-25). 기존 키는 모두 HSM 이다.
ALTER TABLE `keys`
  ADD COLUMN backend VARCHAR(8) NOT NULL DEFAULT 'HSM' COMMENT 'HSM, MPC' AFTER class;
