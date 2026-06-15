---
title: 전처리 — House Prices Prediction
date: 2026-06-15 00:00:00 +0900
categories:
- Machine Learning
tags: []
author: mmamm4
---

# 전처리 — House Prices Prediction

EDA를 끝내고 나니 할 일이 정리는 됐습니다. SalePrice는 로그를 씌워보기로 했고, 결측치는 "시설이 없어서 빈 것"과 "그냥 빠진 것"을 갈라서 다르게 채우기로 했었습니다. 이번 노트는 그 계획을 코드로 옮긴 기록입니다.

솔직히 시작할 때는 결측치만 메우면 금방 끝날 줄 알았습니다. 그런데 test 데이터를 들여다보면서 "이건 어느 쪽 기준으로 채워야 맞지?" 하는 데서 한참 막혔고, 결국 이번 단계에서 제일 많이 배운 것도 거기였습니다.

---

## 로그 변환을 진짜 해도 되는지부터 확인

EDA에서는 "분포가 오른쪽으로 길어서 로그를 씌우면 좋다더라" 정도만 적어뒀습니다. 근거가 좀 빈약하다는 느낌이 있어서, 이번엔 눈으로도 숫자로도 확인하고 넘어가기로 했습니다. 원본과 `np.log1p`를 적용한 값을 나란히 그려봤습니다.

```python
target = train["SalePrice"]
target_log = np.log1p(train["SalePrice"])

fig, axes = plt.subplots(1, 2, figsize=(12, 4))

axes[0].hist(target, bins=40)
axes[0].set_title("Original SalePrice")

axes[1].hist(target_log, bins=40)
axes[1].set_title("Log-transformed SalePrice")

plt.tight_layout()
plt.show()
```

![saleprice_log_transform.png](/assets/img/posts/2026-06-15-02-preprocessing/saleprice_log_transform.png)

왼쪽 원본은 EDA에서 본 그대로 오른쪽으로 쭉 늘어진 모양인데, 오른쪽은 가운데가 봉긋한 종 모양에 꽤 가까워졌습니다. 차이가 생각보다 컸습니다.

그림만으로 "좋아졌다"고 하긴 애매해서 숫자도 봤습니다. 분포가 한쪽으로 얼마나 쏠렸는지를 재는 **왜도(skewness)** 라는 값이 있는데, 0에 가까울수록 좌우 대칭이라고 합니다.

```python
original_skew = skew(target)
log_skew = skew(target_log)

print(f"Original SalePrice skewness: {original_skew:.4f}")
print(f"Log-transformed SalePrice skewness: {log_skew:.4f}")
```

```python
Original SalePrice skewness: 1.8809
Log-transformed SalePrice skewness: 0.1212
```

1.88에서 0.12. 그림에서 받은 인상이 숫자로도 그대로 나왔습니다.

마지막으로 Q-Q plot도 그려봤습니다. 이건 처음 보는 그래프라 한참 헤맸는데, 데이터가 정규분포에 가까우면 점들이 빨간 직선 위에 줄을 선다는 의미라고 합니다.

```python
fig, axes = plt.subplots(1, 2, figsize=(12, 4))

probplot(target, plot=axes[0])
axes[0].set_title("Q-Q Plot: Original SalePrice")

probplot(target_log, plot=axes[1])
axes[1].set_title("Q-Q Plot: Log-transformed SalePrice")

plt.tight_layout()
plt.show()
```

![saleprice_qq_plot.png](/assets/img/posts/2026-06-15-02-preprocessing/saleprice_qq_plot.png)

왼쪽은 오른쪽 위가 직선에서 확 휘어 있습니다. 비싼 집들이 위로 솟구치는 그 모양이 여기서도 똑같이 보였습니다. 오른쪽은 대부분의 점이 직선에 붙어 있고, 양끝만 살짝 들떴습니다.

히스토그램, 왜도, Q-Q plot 셋이 같은 방향을 가리키니, 일단 학습엔 로그 변환한 SalePrice를 쓰기로 했습니다. 물론 진짜로 점수가 좋아지는지는 나중에 모델을 돌려봐야 알겠지만요.

---

## train / test 나누기

결측치를 손대기 전에 학습용 피처와 정답을 분리했습니다.

```python
X_train = train.drop("SalePrice", axis=1).copy()
y_train = train["SalePrice"].copy()
y_train_log = np.log1p(y_train)

X_test = test.copy()

print(X_train.shape)
print(X_test.shape)
```

```python
(1460, 80)
(1459, 80)
```

`SalePrice`를 빼니 train도 test랑 똑같이 80개 컬럼이 됐습니다. 정답은 `y_train`에 따로 두고, 위에서 확인한 로그 버전(`y_train_log`)도 같이 만들어 뒀습니다.

`.copy()`를 붙인 건, 예전에 원본 일부를 잘라 쓰다가 거기에 값을 넣었더니 `SettingWithCopyWarning`이 뜨고 원본까지 건드린 적이 있어서입니다. 정확히 어떤 경우에 view가 되고 어떤 경우에 복사본이 되는지는 아직 헷갈리는데, 일단 새 DataFrame으로 시작할 땐 `.copy()`를 박아두는 쪽이 마음 편했습니다.

---

## 결측치를 한 덩어리로 보지 않기

EDA에서 결측 대부분이 "데이터가 없는 게 아니라 시설이 없는 것"이라는 걸 알았으니, 한꺼번에 채우지 않고 의미별로 갈랐습니다. 그 전에 train과 test 현황을 같이 보려고 작은 함수를 만들었습니다.

```python
def missing_summary(df):
    missing = df.isnull().sum()
    missing = missing[missing > 0].sort_values(ascending=False)
    missing_rate = missing / len(df) * 100
    return pd.DataFrame({
        "missing_count": missing,
        "missing_rate": missing_rate
    })
```

train은 EDA에서 본 19개 컬럼 그대로였는데, test를 찍어보고 좀 당황했습니다. train에선 멀쩡하던 컬럼들에서 test에만 결측이 새로 튀어나왔기 때문입니다.

| 컬럼 | train 결측 | test 결측 |
|------|-----------:|----------:|
| PoolQC | 1,453 | 1,456 |
| MiscFeature | 1,406 | 1,408 |
| MSZoning | 0 | 4 |
| Utilities | 0 | 2 |
| Functional | 0 | 2 |
| Exterior1st | 0 | 1 |
| KitchenQual | 0 | 1 |
| SaleType | 0 | 1 |

(전체 목록 중 일부만 추렸습니다.)

"train엔 없던 결측을 test에서 무슨 수로 채우지?" 여기서 막혔습니다. 결국 이 막힘이 뒤의 데이터 누수 이야기로 이어졌는데, 일단은 결측을 세 부류로 나눴습니다.

- 시설이 없어서 빈 **범주형** → `"None"`
- 시설이 없어서 빈 **수치형** → `0`
- **진짜로 값이 빠진 것** → 통계값(중앙값·최빈값)

### 시설 없음 — 범주형은 "None"

수영장, 골목, 울타리, 벽난로, 차고, 지하실 품질 같은 컬럼들입니다. 시설이 없으면 비는 게 당연하고, 이건 결측이 아니라 "없음"이라는 정보 자체입니다. 그래서 `"None"`이라는 새 범주로 채웠습니다.

```python
none_cat_cols = [
    "PoolQC", "MiscFeature", "Alley", "Fence", "FireplaceQu",
    "GarageType", "GarageFinish", "GarageQual", "GarageCond",
    "BsmtQual", "BsmtCond", "BsmtExposure", "BsmtFinType1", "BsmtFinType2",
    "MasVnrType"
]

for col in none_cat_cols:
    if col in X_train.columns:
        X_train[col] = X_train[col].fillna("None")
    if col in X_test.columns:
        X_test[col] = X_test[col].fillna("None")
```

여기서 `np.nan` 대신 굳이 `"None"`이라는 문자열을 쓴 게 나중에 도움이 될 것 같습니다. 이 중 품질 컬럼들(BsmtQual, GarageQual 등)은 다음 단계에서 Ex > Gd > TA > Fa > Po 순서로 숫자를 매길 텐데, 그때 `"None"`을 0으로 두면 "시설 없음 = 등급 0"으로 자연스럽게 이어집니다. 의도하고 한 건 아니었는데 결과적으로 다음 인코딩과 아귀가 맞았습니다.

### 시설 없음 — 수치형은 0

같은 논리인데 면적이나 개수처럼 숫자인 컬럼들입니다. 차고가 없으면 차고 면적도, 들어가는 차 수도 0이 맞습니다.

```python
none_num_cols = [
    "GarageYrBlt", "GarageArea", "GarageCars",
    "BsmtFinSF1", "BsmtFinSF2", "BsmtUnfSF", "TotalBsmtSF",
    "BsmtFullBath", "BsmtHalfBath",
    "MasVnrArea"
]

for col in none_num_cols:
    if col in X_train.columns:
        X_train[col] = X_train[col].fillna(0)
    if col in X_test.columns:
        X_test[col] = X_test[col].fillna(0)
```

면적·개수는 0이 자연스러운데, `GarageYrBlt`(차고가 지어진 연도)를 0으로 채운 건 좀 찜찜했습니다. 다른 집들 차고 연도는 1900~2010년대인데 여기만 0년이면 숫자상 2천 년쯤 떨어진 값이 되니까요. 일단 "차고 없음"만 표시되면 된다고 보고 0으로 넘어갔는데, 이건 뒤에서 다시 짚겠습니다.

### 진짜 누락 — LotFrontage는 동네별 중앙값

`LotFrontage`(도로와 접한 길이)는 "시설 없음"이 아니라 그냥 기록이 빠진 값입니다. 0이나 "None"으로 채우면 거짓말이 되니, 비슷한 집 값으로 추정해야 했습니다. 같은 동네(Neighborhood)면 부지 모양이 비슷할 것 같아서 동네별 중앙값으로 채웠습니다.

사실 처음 짠 코드는 train은 train끼리, test는 test끼리 따로 중앙값을 냈었습니다. 그게 더 정확할 거라고 생각했거든요. 한참 뒤에야 그게 문제라는 걸 알고(아래 데이터 누수 참고), 중앙값을 train에서만 계산하도록 고쳤습니다.

```python
lotfrontage_median_by_neighborhood = (
    X_train
    .groupby("Neighborhood")["LotFrontage"]
    .median()
)

lotfrontage_global_median = X_train["LotFrontage"].median()

def fill_lotfrontage(df):
    df = df.copy()
    df["LotFrontage"] = df["LotFrontage"].fillna(
        df["Neighborhood"].map(lotfrontage_median_by_neighborhood)
    )
    df["LotFrontage"] = df["LotFrontage"].fillna(lotfrontage_global_median)
    return df

X_train = fill_lotfrontage(X_train)
X_test = fill_lotfrontage(X_test)
```

혹시 어떤 동네가 매핑이 안 될 때를 대비해 전체 중앙값으로 한 번 더 받치는 줄도 넣었습니다. 다만 이건 안전장치일 뿐이고, test에 train에 없는 동네가 실제로 있는지는 아직 확인을 안 했습니다. 이것도 점검 목록에 적어둡니다.

### 진짜 누락 — Electrical, 그리고 test에만 빈 것들

`Electrical`(전기 설비)은 train에서 딱 1개 결측이라 가장 흔한 값(최빈값)으로 채웠습니다. `.mode()`가 값을 여러 개 돌려줄 수 있어서 `[0]`을 붙여야 한다는 걸 이때 알았습니다.

```python
electrical_mode = X_train["Electrical"].mode()[0]
X_train["Electrical"] = X_train["Electrical"].fillna(electrical_mode)

if "Electrical" in X_test.columns:
    X_test["Electrical"] = X_test["Electrical"].fillna(electrical_mode)
```

아까 당황했던, test에만 나타난 범주형 결측들(`MSZoning`, `Utilities`, `KitchenQual`, `SaleType` 등)도 같은 방식으로 채웠습니다. 단, 채우는 값은 전부 train에서 계산했습니다.

```python
test_only_cat_cols = [
    "MSZoning", "Utilities", "Exterior1st", "Exterior2nd",
    "KitchenQual", "Functional", "SaleType"
]

for col in test_only_cat_cols:
    if col in X_train.columns and col in X_test.columns:
        mode_value = X_train[col].mode()[0]
        X_train[col] = X_train[col].fillna(mode_value)
        X_test[col] = X_test[col].fillna(mode_value)
```

여기서 `Functional`은 그냥 최빈값으로 채웠는데, 나중에 data_description.txt를 다시 보니 "NA는 Typ(전형적)으로 본다"고 적혀 있었습니다. 다행히 최빈값도 Typ이라 결과는 같았지만, 원래는 이렇게 설명서가 알려주는 의미대로 채우는 게 더 맞습니다.

---

## 다 채웠는지 검산

여기까지 하고 다시 현황을 찍으니 train·test 모두 빈 표가 나왔습니다. 그래도 제가 목록에서 빠뜨린 컬럼이 있을까 봐, 남은 결측을 타입 보고 알아서 채우는 코드를 한 번 더 돌렸습니다(범주형이면 최빈값, 수치형이면 중앙값, 기준은 역시 train).

```python
remaining_train_missing = X_train.columns[X_train.isnull().sum() > 0]
remaining_test_missing = X_test.columns[X_test.isnull().sum() > 0]
remaining_missing_cols = set(remaining_train_missing) | set(remaining_test_missing)

for col in remaining_missing_cols:
    if col not in X_train.columns or col not in X_test.columns:
        continue
    if X_train[col].dtype == "object":
        fill_value = X_train[col].mode()[0]
    else:
        fill_value = X_train[col].median()
    X_train[col] = X_train[col].fillna(fill_value)
    X_test[col] = X_test[col].fillna(fill_value)
```

마지막엔 전체 결측이 0인지 숫자로 보고, `assert`로 한 번 더 박았습니다.

```python
train_missing_total = X_train.isnull().sum().sum()
test_missing_total = X_test.isnull().sum().sum()

assert train_missing_total == 0
assert test_missing_total == 0
print("결측치 처리가 완료되었습니다.")
```

```python
결측치 처리가 완료되었습니다.
```

`assert`는 이번에 처음 써봤는데, 표를 눈으로 훑는 것보다 마음이 편했습니다. 결측이 하나라도 남으면 여기서 멈추니까, 뒤 단계로 잘못된 데이터가 새어 나갈 일이 없습니다.

---

## test를 train 기준으로 채운 이유 (데이터 누수)

이번 단계에서 제일 헷갈렸던 부분입니다. 중앙값이든 최빈값이든, 채우는 기준값을 **전부 train에서만** 뽑았습니다. test는 그 값을 받아 쓰기만 했습니다. 앞서 LotFrontage에서 test끼리 중앙값을 냈다가 고친 게 바로 이 이유 때문입니다.

처음엔 "test는 test 사정에 맞게 채워야 더 정확하지 않나" 싶었습니다. 그런데 test는 "아직 못 본 미래 데이터"를 흉내 내는 역할이라고 합니다. 실제 서비스라면 새로 들어온 집 한 채를 두고 "이 집들 전체의 중앙값"을 미리 알 수가 없으니까요. 그래서 test의 통계까지 끌어다 쓰면 평가 환경과 어긋나게 되고, 이런 걸 통틀어 **데이터 누수(data leakage)** 라고 부른다는 걸 배웠습니다.

다만 솔직히 적자면, 이 대회의 test에는 정답(SalePrice)이 아예 없습니다. 그래서 엄밀히 말하면 "정답을 엿보는" 누수와는 결이 좀 다릅니다. 그래도 train 기준으로만 통계를 학습하는 습관은 실제 환경에 충실한 올바른 자세라서 그대로 지켰습니다. 더 제대로 하려면 교차검증을 돌릴 때 fold마다 채우는 값을 다시 계산해야 한다는데, 그건 모델링 단계에서 sklearn 파이프라인을 쓰면서 다뤄볼 생각입니다.

---

## 결과 저장

다음 단계에서 바로 불러 쓰게 결과를 파일로 남겼습니다. 정답은 원본과 로그 버전을 둘 다 담았습니다.

```python
X_train.to_csv("/content/X_train_preprocessed.csv", index=False)
X_test.to_csv("/content/X_test_preprocessed.csv", index=False)

pd.DataFrame({
    "SalePrice": y_train,
    "SalePrice_log": y_train_log
}).to_csv("/content/y_train_preprocessed.csv", index=False)
```

---

## 하고 나서야 보인 것들

노트를 정리하면서 다시 코드를 보니, 지금은 넘어갔지만 다음 단계에서 꼭 손봐야 할 것들이 눈에 들어왔습니다. 기록해 둡니다.

- **`Id` 컬럼을 안 뺐습니다.** `X_train`, `X_test`에 `Id`가 그대로 들어 있습니다. 이건 그냥 행 번호라서 집값과 아무 관계가 없는데, 피처로 넣으면 모델이 의미 없는 숫자에 끌릴 수 있습니다. 모델링 전에 빼야 하고, 대신 test의 `Id`는 마지막 제출 파일을 만들 때 필요하니 따로 빼서 보관해 둬야 합니다. 이번에 가장 크게 놓친 부분입니다.

- **이상치(outlier)를 아예 안 봤습니다.** 타겟인 SalePrice 분포만 신경 썼지, 피처 쪽 이상치는 손도 안 댔습니다. 찾아보니 이 데이터셋에서는 거실 면적(`GrLivArea`)이 아주 넓은데 가격은 의외로 싼 집 몇 채가 유명한 이상치라고 합니다. 이런 점들은 회귀선을 통째로 끌어당길 수 있어서, 산점도로 직접 확인하고 뺄지 말지 정해야겠습니다. 이게 어쩌면 `Id`보다 점수에 더 크게 작용할 수도 있을 것 같습니다.

- **숫자처럼 생겼지만 사실은 범주인 컬럼이 있습니다.** `MSSubClass`는 20, 60, 70 같은 정수로 들어 있는데, 이건 크기를 뜻하는 숫자가 아니라 주택 유형 코드입니다. 지금 검산 코드의 자동 채움은 이걸 수치형으로 보고 중앙값을 넣게 되어 있어서 위험합니다. 인코딩 전에 문자열로 바꿔서 범주로 다뤄야 합니다. `MoSold`(판매 월)도 비슷하게 한번 따져볼 생각입니다.

- **`GarageYrBlt`를 0으로 채운 건 다시 봐야 합니다.** 트리 계열 모델(XGBoost 등)은 0이든 1900이든 경계만 나누면 돼서 큰 문제가 없지만, 선형 회귀처럼 숫자 크기를 그대로 쓰는 모델에는 "2천 년 전에 지어진 차고" 같은 이상한 값이 됩니다. 모델을 정하고 나서 0 대신 `YearBuilt`로 채우거나 "차고 있음/없음" 플래그를 따로 두는 걸 비교해보려 합니다.

- **거의 한 가지 값뿐인 컬럼이 있습니다.** `PoolQC`는 채우고 나면 1,453개가 "None"이고, `Utilities`는 사실상 전부 "AllPub"입니다. 이렇게 값이 한쪽으로 쏠린 컬럼은 모델에 주는 정보가 거의 없어서, 통째로 빼는 게 나을 수도 있습니다. 실제로 House Prices 풀이들에서 `Utilities`는 거의 항상 버린다고 합니다. 다만 "거의 상수"인 컬럼을 눈대중이 아니라 수치(예: 한 값의 비율)로 확인한 뒤 정해야겠습니다.

- **짝지어진 컬럼들의 정합성을 확인해야 합니다.** `MasVnrType`(타입)은 "None", `MasVnrArea`(면적)는 0으로 따로 채우다 보니, "타입은 None인데 면적은 0보다 큰" 모순된 행이 남아 있을 수 있습니다. 같은 식으로 지하실(`BsmtQual`↔`TotalBsmtSF`)이나 차고(`GarageType`↔`GarageCars`/`GarageArea`) 묶음도 서로 아귀가 맞는지 한 번 교차로 점검해 봐야겠습니다.

---

## 다음 단계

- `Id` 분리 (피처에서 제거, test의 Id는 제출용으로 보관)
- 피처 이상치 확인 — `GrLivArea` 등 산점도로 보고 제거 여부 결정
- `MSSubClass`·`MoSold` 등 정수로 코딩된 범주형을 문자열로 변환
- 범주형 인코딩 (등급 컬럼은 순서대로 숫자 매기기, 나머지는 원-핫 검토)
- 치우친 수치형 피처(`LotArea`, `GrLivArea`, 지하·현관 면적 등) 골라 로그 변환 적용 검토
- 베이스라인 회귀부터 학습해보고, 로그 타겟으로 점수가 어떻게 달라지는지 확인
- 인코딩·스케일링도 train 기준으로만 학습하도록 누수 주의 (모델링 단계에서 파이프라인으로)
